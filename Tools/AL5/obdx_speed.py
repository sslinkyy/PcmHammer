"""Offline speed evidence interpretation. No serial, timers, or send operations.

VPW candidates follow PcmHammer Messages/Protocol.Speed.cs, not a proven
EFILive/AL5 transition contract. Device configuration never establishes bus rate.
"""


class SpeedEvidence:
    def __init__(self, emit):
        self.emit = emit
        self.packet_ordinal = 0
        self.network_state = None
        self.crc_display = None
        self.adapter_speed = None
        self.pending = None
        self.set_target = None
        self.prepare_tool = None
        self.prepare_target = None
        self.grants = set()
        self.refusals = set()
        self.events = {}
        self.risks = {}
        self.finished = False
        self.correlation_usable = True

    def clear_negotiation(self):
        self.prepare_tool = self.prepare_target = None
        self.grants.clear()
        self.refusals.clear()

    def discontinuity(self, reason, source_line):
        if self.pending is not None:
            self.risk('unfinished_speed_request_at_discontinuity', source_line,
                      request_source_line=self.pending['source_line'])
        if self.set_target is not None:
            self.risk('speed_set_without_readback_at_discontinuity', source_line,
                      requested_speed=self.set_target)
        self.risk(reason, source_line)
        self.pending = None
        self.set_target = None
        self.adapter_speed = None
        self.correlation_usable = False
        self.clear_negotiation()

    def event(self, name, source_line, **facts):
        self.events[name] = self.events.get(name, 0) + 1
        self.emit({'kind': 'speed_evidence', 'event': name,
                   'source_line': source_line, 'receive_packet_ordinal': self.packet_ordinal,
                   'adapter_speed_readback': self.adapter_speed,
                   'reported_network_state': self.network_state,
                   'actual_bus_speed': 'unknown', **facts})

    def risk(self, name, source_line, **facts):
        self.risks[name] = self.risks.get(name, 0) + 1
        self.event('capture_gap_risk', source_line, reason=name, **facts)

    def outgoing(self, command, payload, source_line):
        p = bytes(payload)
        if command != 0x33 or p not in (b'\x06', b'\x06\x00', b'\x06\x01'):
            return
        ambiguous = self.pending is not None
        if ambiguous:
            self.risk('overlapping_speed_requests', source_line)
            self.correlation_usable = False
            self.adapter_speed = None
        action = 'get' if len(p) == 1 else 'set'
        self.pending = {'action': action, 'source_line': source_line,
                        'payload': p, 'ambiguous': ambiguous or not self.correlation_usable}
        if action == 'set':
            self.set_target = '4x' if p[1] else '1x'
            self.adapter_speed = None  # settings may change before readback
            self.event('adapter_speed_set_requested', source_line,
                       requested_speed=self.set_target)

    def received(self, row):
        self.packet_ordinal += 1
        line = row.get('source_line_end')
        command = row['command']
        p = bytes.fromhex(row['payload_hex'])
        if command == 0x41 and len(p) == 2 and p[0] == 2 and p[1] <= 2:
            state = ('off', 'on', 'listen_only')[p[1]]
            if state != self.network_state or state == 'off':
                self.clear_negotiation()
            self.network_state = state
        if command == 0x43 and len(p) == 2 and p[0] == 8 and p[1] <= 1:
            self.crc_display = bool(p[1])
        if command == 0x7F and self.pending is not None:
            self.risk('adapter_error_while_speed_request_pending', line, raw_payload_hex=p.hex())
            self.pending = None
            self.adapter_speed = None
            self.correlation_usable = False
            self.clear_negotiation()
        if command == 0x43 and p[:1] == b'\x06':
            self.speed_status(p, line)
        if row['kind'] == 'network':
            self.network_packet(p, line)

    def speed_status(self, p, line):
        if len(p) != 2 or p[1] not in (0, 1):
            self.adapter_speed = None
            self.pending = None
            self.risk('unknown_speed_status', line, raw_payload_hex=p.hex())
            self.correlation_usable = False
            return
        reported = '4x' if p[1] else '1x'
        pending, self.pending = self.pending, None
        if pending is None or pending['ambiguous']:
            self.adapter_speed = None
            self.event('uncorrelated_speed_status', line, reported_speed=reported)
            return
        if pending['action'] == 'set':
            matched = p == pending['payload']
            self.event('adapter_speed_set_acknowledged' if matched else 'adapter_speed_ack_mismatch',
                       line, reported_speed=reported, request_source_line=pending['source_line'])
            if not matched:
                self.risk('speed_acknowledgment_mismatch', line)
            return  # an echo is not a separate readback
        previous = self.adapter_speed
        self.adapter_speed = reported
        self.event('adapter_speed_readback', line, reported_speed=reported,
                   previous_readback=previous, request_source_line=pending['source_line'],
                   scope='network_off_configuration' if self.network_state == 'off'
                         else 'adapter_configuration')
        if self.set_target is not None:
            if reported != self.set_target:
                self.risk('speed_set_readback_mismatch', line, requested_speed=self.set_target,
                          reported_speed=reported)
            self.set_target = None

    def network_packet(self, payload, line):
        if self.network_state == 'off':
            self.risk('network_frame_while_reported_off', line)
            self.clear_negotiation()
            return  # bytes may be stale; do not build current negotiation context
        if self.crc_display is None:
            # A fourth byte could be a CRC on a three-byte header, not a service.
            if len(payload) >= 4 and payload[3] in (0xA0, 0xA1, 0xE0, 0x75, 0x7F):
                self.event('ambiguous_vpw_crc_layout', line, payload_hex=payload.hex())
            return
        p = payload[:-1] if self.crc_display else payload
        if len(p) < 4 or p[0] != 0x6C:
            return
        destination, source, service = p[1:4]
        tool = 0xF0 <= source <= 0xFD
        if tool and (destination <= 0xEF or destination == 0xFE):
            if len(p) == 4 and service == 0xA0:
                self.prepare_tool, self.prepare_target = source, destination
                self.grants.clear()
                self.refusals.clear()
                self.event('high_speed_permission_request_candidate', line,
                           source_id=source, destination_id=destination)
            elif len(p) == 4 and service == 0xA1:
                context = (source == self.prepare_tool
                           and self.prepare_target in (0xFE, destination))
                self.event('begin_high_speed_candidate', line, source_id=source,
                           destination_id=destination,
                           permission_context_seen=context,
                           permission_sources=sorted(self.grants) if context else [],
                           refusal_sources=sorted(self.refusals) if context else [])
                if self.adapter_speed != '4x':
                    self.risk('begin_without_adapter_4x_readback', line)
                if context and self.refusals:
                    self.risk('begin_after_refusal_candidate', line)
                self.clear_negotiation()  # a later begin must not reuse old permissions
            return
        if not 0xF0 <= destination <= 0xFD or source > 0xEF:
            return
        addressed_to_prepare_tool = (destination == self.prepare_tool and source <= 0xEF
                                    and self.prepare_target in (0xFE, source))
        if len(p) == 4 and service == 0xE0:
            if addressed_to_prepare_tool:
                self.grants.add(source)
            self.event('high_speed_permission_reply_candidate', line,
                       source_id=source, correlated_request=addressed_to_prepare_tool)
        elif len(p) in (5, 6) and service in (0x75, 0x7F) and p[4] in (0xA0, 0xA1):
            if addressed_to_prepare_tool:
                self.refusals.add(source)
            self.event('high_speed_refusal_candidate', line, source_id=source,
                       rejected_service=p[4], correlated_request=addressed_to_prepare_tool)

    def summary(self):
        if not self.finished:
            if self.pending is not None:
                self.risk('unfinished_speed_request', self.pending['source_line'])
            if self.set_target is not None:
                self.risk('speed_set_without_separate_readback', None)
            self.finished = True
        return {'event_counts': dict(self.events), 'gap_risk_counts': dict(self.risks),
                'final_adapter_speed_readback': self.adapter_speed,
                'speed_response_correlation_usable': self.correlation_usable,
                'actual_bus_speed': 'unknown', 'automatic_speed_tracking': False,
                'transition_continuity_proven': False}
