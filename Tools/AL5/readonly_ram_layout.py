"""Candidate RAM placement only; not an assertion of physical ownership or a live handoff plan."""
CODE_BASE=0xFF9006
RAM=(0xFF8000,0xFFB800)
FIXED=(('state',0xFFA300,0xFFA314),('receive',0xFFA380,0xFFA39A),('transmit',0xFFA400,0xFFA43A),
       ('request',0xFFA500,0xFFA516),('reply',0xFFA600,0xFFA636),('stack',0xFFA700,0xFFA800))
def audit(code_bytes):
 if not isinstance(code_bytes,int) or code_bytes<=0 or CODE_BASE+code_bytes>0xFFA000:raise ValueError('Code outside bounded experimental text region')
 regions=[('code',CODE_BASE,CODE_BASE+code_bytes),*FIXED]
 for name,a,b in regions:
  if not RAM[0]<=a<b<=RAM[1]:raise ValueError('Outside candidate readable-RAM interval')
 for i,(_,a,b) in enumerate(regions):
  if any(a<d and b>c for _,c,d in regions[i+1:]):raise ValueError('Overlapping candidate owners')
 return dict(regions=[dict(owner=n,start=a,end_exclusive=b,bytes=b-a) for n,a,b in regions],
   candidate_layout_nonoverlapping=True,physical_ram_ownership_proven=False,requires_exclusive_handoff=True,
   captured_sps_code_overlap_bytes=max(0,min(CODE_BASE+code_bytes,0xFF9F18)-CODE_BASE),
   hardware_interrupts_quiescent_proven=False,live_upload_enabled=False,live_execution_enabled=False,
   limits=['Native permission table is not a physical SRAM ownership proof.',
     'This code region overlaps the historical SPS loader; concurrent coexistence is not supported.',
     'Resident global RAM, exception vectors, DMA and nonmaskable events are not qualified.'])
