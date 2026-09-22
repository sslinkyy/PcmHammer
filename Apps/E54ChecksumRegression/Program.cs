// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using PcmHacking;
using Tests;

internal static class Program
{
    // Synthetic images only. No OEM binaries or hardware access required.
    private static void Word(byte[] image, int address, int value)
    {
        image[address] = (byte)(value >> 8);
        image[address + 1] = (byte)value;
    }

    private static void Long(byte[] image, int address, uint value)
    {
        Word(image, address, (int)(value >> 16));
        Word(image, address + 2, (int)value);
    }

    private static void Repair(byte[] image, int header, int end)
    {
        int sum = 0;
        for (int p = header + 2; p <= end; p += 2)
            sum = (sum + (image[p] << 8) + image[p + 1]) & 0xFFFF;
        Word(image, header, (-sum) & 0xFFFF);
    }

    private static byte[] Image(uint osid = 15189044)
    {
        var image = new byte[0x80000];
        Long(image, 0x20004, osid);
        // Match the known calibration boundary table, including nonzero Fuel data.
        int[] boundaries = { 0x8000, 0x19FFF, 0x1A000, 0x1C7FF,
                             0x1C800, 0x1DFFF, 0x1E000, 0x1EFFF, 0x1F000, 0x1FFEF };
        for (int i = 0; i < boundaries.Length; i++)
            Long(image, 0x20012 + i * 4, (uint)boundaries[i]);
        Word(image, 0x1C820, 0x1234);
        Repair(image, 0x1C800, 0x1DFFF);
        Repair(image, 0x20000, 0x6FFFF);
        return image;
    }

    private static void Check(string name, byte[] image, bool expected)
    {
        byte[] before = (byte[])image.Clone();
        bool actual = new FileValidator(image, new MockLogger(), PcmType.E54).IsValid();
        if (actual != expected)
            throw new Exception(name + ": expected " + expected + ", got " + actual);
        if (!before.SequenceEqual(image))
            throw new Exception(name + ": validator modified the input");
        Console.WriteLine("PASS: " + name);
    }

    private static int Main()
    {
        try
        {
            Check("valid known layout", Image(), true);
            var image = Image();
            image[0x1C820] ^= 1;
            Check("unrepaired Fuel corruption rejected", image, false);
            Repair(image, 0x1C800, 0x1DFFF);
            Check("correctly repaired Fuel edit accepted", image, true);

            image = Image();
            image[0x1C010] = 1;
            Repair(image, 0x1A000, 0x1C7FF);
            Check("valid diagnostics-tail edit accepted", image, true);

            image = Image();
            image[0x1C820] ^= 1;
            // Reproduce the old false acceptance; this is not PCMHammer repair behavior.
            Repair(image, 0x1C000, 0x1DFFF);
            Repair(image, 0x1A000, 0x1C7FF);
            Check("compensation at wrong header cannot conceal invalid Fuel", image, false);

            image = Image();
            image[0x1C800] ^= 1;
            Check("Fuel checksum-word corruption rejected", image, false);

            image = Image();
            image[0x1C7FE] = 1;
            Check("diagnostics corruption still rejected", image, false);

            Check("other OS baseline retains legacy behavior", Image(15166853), true);
            image = Image(15166853);
            image[0x1C010] = 1;
            Repair(image, 0x1A000, 0x1C7FF);
            Check("other OS still uses original Fuel range", image, false);
            Check("truncated E54 rejected", new byte[0x20008], false);
            Console.WriteLine("All 10 E54 checksum regressions passed; input immutability checked.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
