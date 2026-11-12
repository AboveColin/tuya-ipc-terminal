package tuya

import "testing"

func TestPartnerFromUsername(t *testing.T) {
	cases := []struct{ username, want string }{
		{"p2065237_v1_7gqdt8hrgamaxeksxchg_ch_mb_sid0123456789abcdef", "p2065237"},
		{"p2645382_v1_d997esphw5fevawrcyud_ch_mb_sid0123456789abcdef", "p2645382"},
		{"", defaultPartnerID},
		{"no-version-marker", defaultPartnerID},
		{"_v1_app_ch_mb_sid", defaultPartnerID},
		{"a_b_v1_app", defaultPartnerID},
	}
	for _, c := range cases {
		if got := partnerFromUsername(c.username); got != c.want {
			t.Errorf("partnerFromUsername(%q) = %q, want %q", c.username, got, c.want)
		}
	}
}
