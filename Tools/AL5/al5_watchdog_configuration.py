"""Conditional MC68336/376 SYPCR write-once observer, not a physical timer."""


class ConditionalWatchdogConfiguration:
    def __init__(self,*,fresh_reset,inherited_value=None):
        if type(fresh_reset) is not bool or (inherited_value is not None and (type(inherited_value) is not int or not 0<=inherited_value<=255)):
            raise ValueError('Explicit reset hypothesis and optional byte value required')
        if fresh_reset and inherited_value is not None:raise ValueError('Fresh reset does not identify a retained effective value')
        self.available=fresh_reset;self.value=inherited_value;self.attempts=[]

    def observe(self,*,pc,phase,value):
        if type(pc) is not int or not 0<=pc<=0xFFFFFFFF or type(phase) is not str or not phase or type(value) is not int or not 0<=value<=255:
            raise ValueError('Observed control attempt requires pc, phase and a byte')
        accepted=self.available;before=self.value
        if accepted:self.value=value;self.available=False
        self.attempts.append(dict(pc=pc,phase=phase,attempted_value=value,conditionally_accepted=accepted,effective_before=before,effective_after=self.value))

    def snapshot(self):
        value=self.value;enabled=None if value is None else bool(value&0x80)
        prescaled=None if value is None else bool(value&0x40);timing=None if value is None else (value>>4)&3
        cycles=None if not enabled else 1<<(9+2*timing+(9 if prescaled else 0))
        return dict(effective_value_under_hypothesis=value,enabled_under_hypothesis=enabled,
            prescaled_under_hypothesis=prescaled,timing_field_under_hypothesis=timing,
            timeout_system_clock_cycles_under_hypothesis=cycles,attempts=[dict(row) for row in self.attempts],
            source_clock_hz=None,timeout_seconds=None,actual_mcu_identified=False,
            physical_configuration_verified=False,physical_timeout_verified=False)
