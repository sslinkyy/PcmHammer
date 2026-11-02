using System;
using System.Linq;
using PcmHacking;

static class CalibrationSectorPlanTest
{
 static void Check(bool value){if(!value)throw new Exception("Sector policy assertion failed");}
 static void Reject(Action action){try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected sector policy rejection");}
 static byte[] Calibration()
 {
  var b=new byte[AL5CalibrationInspection.Length];
  foreach(var pair in new[]{(0x8024,"00E7B058"),(0xA996,"11F70C68073E05A0040002D9"),(0x158A8,"00110009"),(0x15FD4,"507CCC15")})
   Convert.FromHexString(pair.Item2).CopyTo(b,pair.Item1-0x8000);
  return b;
 }
 static void Main()
 {
  // Datasheet Table 3 byte-address golden; independent of the geometry implementation.
  uint[] starts={0,0x4000,0x6000,0x8000,0x10000,0x20000,0x30000,0x40000,0x50000,0x60000,
                 0x70000,0x80000,0x90000,0xA0000,0xB0000,0xC0000,0xD0000,0xE0000,0xF0000,0x100000};
  for(int i=0;i<19;i++){var sector=AL5CalibrationSectorPlan.Sector(i);Check(sector.Index==i && sector.Start==starts[i] && sector.EndExclusive==starts[i+1]);}
  Reject(()=>AL5CalibrationSectorPlan.Sector(-1));Reject(()=>AL5CalibrationSectorPlan.Sector(19));
  Check(AL5CalibrationSectorPlan.CopyCalibrationEraseSectorStarts().SequenceEqual(new uint[]{0x8000,0x10000}));
  foreach(uint address in starts.Take(19))
   if(address==0x8000 || address==0x10000)AL5CalibrationSectorPlan.ValidateSectorErase(address);
   else Reject(()=>AL5CalibrationSectorPlan.ValidateSectorErase(address));
  foreach(uint address in new uint[]{0x8002,0xFFFF,0x10002,0x1FFFE,uint.MaxValue})Reject(()=>AL5CalibrationSectorPlan.ValidateSectorErase(address));
  Reject(AL5CalibrationSectorPlan.ValidateChipErase);
  foreach(var span in new[]{(0x8000u,2),(0xFFFEu,4),(0x15FD8u,40998),(0x8000u,98302),(0x1FFFCu,2)})
   AL5CalibrationSectorPlan.ValidateProgramSpan(span.Item1,span.Item2);
  foreach(var span in new[]{(0xAAAu,2),(0x554u,2),(0x2000u,2),(0x4000u,2),(0x6000u,2),(0x7FFEu,4),
                           (0x8001u,2),(0x8000u,0),(0x8000u,-2),(0x8000u,3),(0x1FFFCu,4),
                           (0x1FFFEu,2),(0x20000u,2),(0xFFFFFFFEu,4),(0x8000u,int.MaxValue-1)})
   Reject(()=>AL5CalibrationSectorPlan.ValidateProgramSpan(span.Item1,span.Item2));
  AL5CalibrationSectorPlan.ValidateFinalizationSpan(0x1FFFE,2);
  foreach(var span in new[]{(0x1FFFCu,4),(0x1FFFEu,4),(0x8000u,2),(0x1FFFEu,-2)})
   Reject(()=>AL5CalibrationSectorPlan.ValidateFinalizationSpan(span.Item1,span.Item2));
  var calibration=Calibration();var before=Enumerable.Range(0,98304).Select(i=>(byte)(i^(i>>8))).ToArray();
  before[^2]=0x12;before[^1]=0x34;var original=(byte[])before.Clone();
  var plan=new AL5CalibrationSectorPlan(calibration,before);
  Check(plan.SavedOriginalMarker==0x1234);
  var desired=plan.CopyDesiredBeforeFinalization();Check(desired.Take(calibration.Length).SequenceEqual(calibration));
  Check(desired.Skip(calibration.Length).SequenceEqual(original.Skip(calibration.Length)));
  Check(!plan.AssessSavedReadback(desired).ExactSavedImageMatch);
  desired[^2]=0x4A;desired[^1]=0xFC;Check(plan.AssessSavedReadback(desired).ExactSavedImageMatch);
  foreach(int index in new[]{0,calibration.Length,desired.Length-1})
  {var changed=(byte[])desired.Clone();changed[index]^=1;Check(!plan.AssessSavedReadback(changed).ExactSavedImageMatch);}
  before[0]^=1;before[^1]^=1;calibration[0]^=1;
  Check(plan.CopySavedPreEraseSectors().SequenceEqual(original) && plan.SavedOriginalMarker==0x1234);
  var returned=plan.CopyCollateralBackup();returned[0]^=1;Check(plan.CopyCollateralBackup()[0]!=returned[0]);
  Reject(()=>new AL5CalibrationSectorPlan(Calibration(),new byte[98302]));
  Reject(()=>new AL5CalibrationSectorPlan(Calibration(),new byte[41000]));
  Reject(()=>new AL5CalibrationSectorPlan(Calibration(),new byte[98306]));
  Reject(()=>new AL5CalibrationSectorPlan(new byte[57304],original));
  Reject(()=>plan.AssessSavedReadback(new byte[57304]));
  Check(!plan.LiveUploadEnabled && !plan.LiveExecutionEnabled && !plan.LiveWriteEnabled && !plan.ReadyToFlash && !plan.PhysicalSectorMappingVerified && !plan.IndependentBackupVerified);
  var report=plan.AssessSavedReadback(desired);Check(!report.LiveWriteEnabled && !report.ReadyToFlash && !report.PhysicalReadbackVerified && !report.RecoveryVerified);
  Console.WriteLine("PASS bottom-boot byte geometry, calibration-sector allowlist, overflow/alignment/protected-range rejection, separate finalization and exact collateral/marker preservation; live gates closed.");
 }
}
