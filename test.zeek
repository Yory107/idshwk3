global a:table[addr] of string;
global b:table[addr] of string;


event http_header(C:connection, is_orig:bool, name:string, value:string)
	{
		local ip = C$id$orig_h;
		#print ip;
		
		if( [ip] !in a)
			a[ip] = name;
		else
			if( [ip] !in b)
				b[ip] = name;
			else
				if(a[ip] != name && b[ip] != name)
					print ip,"is a proxy";
	}
