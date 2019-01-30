module github.com/acobaugh/check_ldap_cert

require (
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v3 v3.0.0
)

replace gopkg.in/ldap.v3 => /home/acobaugh/go/src/github.com/go-ldap/ldap
