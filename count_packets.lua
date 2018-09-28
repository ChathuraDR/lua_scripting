local httpcounter = 0
local smbcounter = 0
local icmpcounter = 0
local vrrpcounter = 0


local function listenerfunction()
	local listener = Listener.new(nil, '') --creating a listner with no filters, normally the filters are 'http' and etc.

	-- holds our fields for each packet

	local proto = Field.new('ip.proto')
	local httpfield = Field.new('http')
	local smbfield = Field.new('smb')
	local icmpfield = Field.new('icmp')
	local vrrpfield = Field.new('vrrp')	-- virtual rouder redundancy protocol

	-- define the fields before you define the callback function
	
	function listener.packet(pinfo, tvb)
		-- This is called for every packet meeting the filter,
		local protocolnumber = proto()

		-- check to see if the packet has an ICMP field, if so increment the ICMP counter
		if(icmpfield()) then
			icmpcounter = icmpcounter + 1
		end

		-- check to see if the packet has an VRRP field, if so increment the VRRP counter
		if(vrrpfield()) then
			vrrpcounter = vrrpcounter + 1
		end

		-- if the IP protocol is 6, it's TCP
		if(protocolnumber and protocolnumber.value == 6) then	-- IP protocol number is the IP field that tells what the lower layer protocol is
		
		-- 6 specifies that the IP packet is encapsulating a TCP packet
		-- because smb, http are going over TCP, here we're checking those fields on TCP packets rather than checking them on evry packets
		
			local http = httpfield()
			local smb = smbfield()
			
			if http then
				httpcounter = httpcounter + 1
			end
			if smb then
				smbcounter = smbcounter + 1
			end
		end
	end
	
	-- create the draw function which will display our counters
	function listener.draw()
		-- string.format function here will convert variables to string
		print(string.format("HTTP: %i", httpcounter))
		print(string.format("SMB: %i", smbcounter))
		print(string.format("VRRP: %i", vrrpcounter))
		print(string.format("ICMP: %i", icmpcounter))
	end

end


listenerfunction()
