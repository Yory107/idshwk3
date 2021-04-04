global a:table[addr] of string;
global b:table[addr] of string;


event http_entity_data(C:connection, is_orig:bool, length:count, data:string)
	{
                if(!C$http?$user_agent)
                        return;
		local ip = C$id$orig_h;
                local agt = C$http$user_agent;
		#print ip;
		#print agt;
		if( [ip] !in a)
			a[ip] = agt;
		else
		{
			if( a[ip] == agt )
			return;
			if( [ip] !in b)
				b[ip] = agt;
			else
			{
				if(a[ip] != agt && b[ip] != agt)
					print ip,"is a proxy";
			}
		}
	}
