module LogFilter;

const ignore_ports_resp: set[port] = {80/udp, 80/tcp, 123/udp, 137/udp, 161/udp, 514/udp, 514/tcp, 5355/udp, 5666/tcp, 8443/tcp} &redef;
const ignore_services: set[string] = {"dns"} &redef;

event zeek_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name = "conn-noise",
                        $path_func(id: Log::ID, path: string, rec: Conn::Info) = {

                                return (rec$id$resp_p in ignore_ports_resp) ? "conn-noise" : "conn";
                        }]);
}
