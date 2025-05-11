package utils

import (
	"github.com/miekg/dns"
)

func GetCNAME(domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil || len(r.Answer) == 0 {
		return "", err
	}

	for _, ans := range r.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}

	return "", nil
}
