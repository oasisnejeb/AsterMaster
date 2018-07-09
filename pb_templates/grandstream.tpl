<?xml version="{{ data.xver }}" encoding="{{ data.encoding }}"?>
<AddressBook>
	{% for phone,name in data.users.iteritems() -%}
	<Contact>
		<FirstName>{{ name }}</FirstName>
		<Phone>
			<phonenumber>{{ phone }}</phonenumber>
			<accountindex>{{ data.accountindex }}</accountindex>
		</Phone>
		<Groups>
			<groupid>{{ data.group }}</groupid>
		</Groups>
	</Contact>
	{%- endfor %}
</AddressBook>