module LogFilter;

event zeek_init()
{
        Log::remove_default_filter(DNS::LOG);
        Log::add_filter(DNS::LOG, [$name = "dns-noise",
                        $path_func(id: Log::ID, path: string, rec: DNS::Info) = {
                                return (rec?$query && /.mozilla.(org|net|com)$|.github.(io|com)$|cybersapien.tech$/ in rec$query) ? "dns-noise" : "dns";
                        }]);
}


