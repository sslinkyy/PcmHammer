using System;
using System.IO;
using System.Security.Cryptography;
using PcmHacking;

internal static class CapturedProgramImageTest
{
    static byte[] Example(int address, int count, byte value = 0)
    {
        var p = new byte[count+12];
        p[0]=0x6D; p[1]=0x18; p[2]=0xF0; p[3]=0x36;
        p[5]=(byte)(count>>8); p[6]=(byte)count;
        p[7]=(byte)(address>>16); p[8]=(byte)(address>>8); p[9]=(byte)address;
        for(int i=0;i<count;i++) p[10+i]=value;
        int sum=0; for(int i=4;i<p.Length-2;i++) sum+=p[i];
        p[p.Length-2]=(byte)(sum>>8); p[p.Length-1]=(byte)sum;
        return p;
    }
    static void Check(bool value) { if(!value) throw new Exception("Capture assertion failed"); }
    static void Reject(Action action) { try { action(); } catch(ArgumentException) { return; } throw new Exception("Invalid input accepted"); }
    static int Main(string[] args)
    {
        var image=new AL5CapturedProgramImage();
        var first=Example(0x8000,512); image.Observe(first); image.Observe(first);
        Check(image.CoveredBytes==512 && image.AcceptedRequests==2);
        Reject(()=>image.Observe(Example(0x8000,512,1)));
        Reject(()=>image.Observe(Example(0x7FFE,2)));
        Reject(()=>image.Observe(Example(0x1FFFE,2)));
        Reject(()=>image.Observe(Example(0x8001,2)));
        Reject(()=>image.Observe(Example(0x8200,514)));
        var corrupt=Example(0x8200,512); corrupt[10]^=1; Reject(()=>image.Observe(corrupt));
        Check(image.AcceptedRequests==2 && image.CoveredBytes==512);
        try { image.CopyCompleteImage(); throw new Exception("Invented missing bytes"); } catch(InvalidOperationException) { }
        for(int address=0x8200;address<0x1FFFE;address+=512)
            image.Observe(Example(address,Math.Min(512,0x1FFFE-address)));
        Check(image.Complete && image.CoveredBytes==98302 && !image.LiveWriteEnabled && !image.RecoveryVerified);
        var owned=image.CopyCompleteImage(); owned[0]=1; Check(image.CopyCompleteImage()[0]==0);
        var calibration=new byte[AL5CalibrationInspection.Length];
        foreach(var pair in new[]{(0x8024,"00E7B058"),(0xA996,"11F70C68073E05A0040002D9"),
                                 (0x158A8,"00110009"),(0x15FD4,"507CCC15")})
            Convert.FromHexString(pair.Item2).CopyTo(calibration,pair.Item1-0x8000);
        var collateral=new byte[AL5ProgrammingWorkflow.CollateralLength];
        var joined=new byte[98302]; calibration.CopyTo(joined,0);
        var referenceImage=new AL5CapturedProgramImage();
        for(int offset=0;offset<joined.Length;offset+=512)
        {
            int count=Math.Min(512,joined.Length-offset); var packet=Example(0x8000+offset,count);
            Array.Copy(joined,offset,packet,10,count);
            int sum=0; for(int n=4;n<packet.Length-2;n++) sum+=packet[n];
            packet[packet.Length-2]=(byte)(sum>>8);packet[packet.Length-1]=(byte)sum;
            referenceImage.Observe(packet);
        }
        var assessment=referenceImage.AssessReference(calibration,collateral);
        Check(!assessment.LiveWriteEnabled && !assessment.ReadyToFlash);
        collateral[0]=1;Reject(()=>referenceImage.AssessReference(calibration,collateral));
        if(args.Length%2!=0) throw new ArgumentException("Use CORPUS EXPECTED_IMAGE_SHA256 pairs");
        for(int i=0;i<args.Length;i+=2)
        {
            var captured=new AL5CapturedProgramImage();
            foreach(var line in File.ReadLines(args[i])) captured.Observe(Convert.FromHexString(line));
            var hash=Convert.ToHexString(SHA256.HashData(captured.CopyCompleteImage())).ToLowerInvariant();
            Check(hash==args[i+1] && !captured.LiveWriteEnabled);
            Console.WriteLine("PASS pinned corpus "+Path.GetFileName(args[i])+": "+captured.AcceptedRequests+" requests; "+captured.CoveredBytes+" bytes");
        }
        Console.WriteLine("PASS offline bounds, checksum, conflict atomicity, duplicate, gap and ownership checks. No transport linked.");
        return 0;
    }
}
