using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ptpwn
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (var process in Process.GetProcesses())
            {
                if (process.ProcessName != "PacketTracer6" &&
                    process.ProcessName != "PacketTracer7")
                    continue;

                var ptr = NativeMethods.OpenProcess(0x001F0FFF, true, process.Id);
                if (ptr == IntPtr.Zero)
                    Die();

                var version = ReadVersion(ptr);
                if (version == null)
                    Die("unknown packet tracer version");

                DoMagic(ptr, version);
            }
        }

        static void DoMagic(IntPtr handle, PacketTracer version)
        {
            //replace the instruction at version.Target with a jmp rel32 instruction
            //the goal is to skip all of the checks and warnings related to user profile changes
            unchecked
            {
                //calculate how far we need to jump
                //-5 because the jmp rel32 instruction is 5 bytes long
                uint dist = (uint)version.EndpointPtr.ToInt32() - (uint)version.TargetPtr.ToInt32() - 5u;

                WriteMemory(handle,
                   version.TargetPtr,
                   new byte[] { 0xE9, (byte)dist, (byte)(dist >> 8), (byte)(dist >> 16), (byte)(dist >> 24) }
               );
            }
        }

        static PacketTracer ReadVersion(IntPtr process)
        {
            foreach (var version in _versions)
            {
                var versionBytes = ReadMemory(process, version.VersionPtr, (uint)version.ToString().Length);
                try
                {
                    if (Encoding.ASCII.GetString(versionBytes) == version.ToString())
                        return version;
                }
                catch { }
            }

            return null;
        }

        static byte[] ReadMemory(IntPtr process, IntPtr address, uint length)
        {
            uint read = 0;
            byte[] buffer = new byte[length];

            if (!NativeMethods.ReadProcessMemory(process, address, buffer, length, ref read))
                Die();

            if (read != length)
                Die("could not read requested amount of bytes");

            return buffer;
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte[] buffer)
        {
            uint written = 0;
            if (!NativeMethods.WriteProcessMemory(process, address, buffer, (uint)buffer.Length, ref written))
                Die();

            if (written != (uint)buffer.Length)
                Die("could not write requested amount of bytes");
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte b)
        {
            WriteMemory(process, address, new byte[] { b });
        }

        static void Die()
        {
            throw new Exception(string.Format("fuck: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        static void Die(string message)
        {
            throw new Exception(message);
        }

        static PacketTracer[] _versions =
        {
            new PacketTracer(new IntPtr(0x0281F628), new IntPtr(0x00C78633), new IntPtr(0x00C78880), "6.2.0.0052"),
            new PacketTracer(new IntPtr(0x02D97670), new IntPtr(0x00C823C3), new IntPtr(0x00C82610), "6.3.0.0009"),
            new PacketTracer(new IntPtr(0x02B2984C), new IntPtr(0x00CFC423), new IntPtr(0x00CFC6A9), "7.0.0.0201"),
        };
    }

    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
    }

    class PacketTracer
    {
        public readonly IntPtr VersionPtr;
        public readonly IntPtr TargetPtr;
        public readonly IntPtr EndpointPtr;

        private string _version;

        public PacketTracer(IntPtr versionPtr, IntPtr targetPtr, IntPtr endpointPtr, string versionString)
        {
            VersionPtr = versionPtr;
            TargetPtr = targetPtr;
            EndpointPtr = endpointPtr;
            _version = versionString;
        }

        public override string ToString()
        {
            return _version;
        }
    }
}