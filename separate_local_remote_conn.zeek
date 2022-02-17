# Note: if using ZeekControl then you don't need to redef local_nets.
# redef Site::local_nets = { 192.168.0.0/16 };

function myfunc(id: Log::ID, path: string, rec: Conn::Info) : string
    {
	    # Return "conn-local" if originator is a local IP, otherwise
	    # return "conn-remote".
	    local r = Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
	    return fmt("%s-%s", path, r);
    }

event zeek_init()
    {
    local filter: Log::Filter = [$name="conn-split",
             $path_func=myfunc, $include=set("ts", "id.orig_h")];
    Log::add_filter(Conn::LOG, filter);
    }


