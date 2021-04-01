global a:table[addr] of string;
global b:table[addr] of string;


event http_header(C:connection, is_orig:bool, name:string, value:string)
	{
		local ip = C$id$orig_h;
                local agt = C$http$user_agent;
		#print ip;
		
		if( [ip] !in a)
			a[ip] = agt;
		else
			if( [ip] !in b)
				b[ip] = agr;
			else
				if(a[ip] != agt && b[ip] != agt)
					print ip,"is a proxy";
	}
