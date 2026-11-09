package recursor

import (
	"bytes"
	"slices"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

func TestCanonicalOrder(t *testing.T) {
	// RFC 4034 section 6.1
	names := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.",
		"z.example.", "\x01.z.example.", "*.z.example.", "\xc8.z.example."}
	wire := make([]string, len(names))
	for i, n := range names {
		var b []byte
		for _, l := range bytes.Split([]byte(n[:len(n)-1]), []byte(".")) {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		wire[i] = string(b)
	}
	shuffled := slices.Clone(wire)
	slices.Reverse(shuffled)
	slices.SortFunc(shuffled, canonicalCompare)
	if !slices.Equal(shuffled, wire) {
		t.Fatalf("order: %q", shuffled)
	}
}

func TestNames(t *testing.T) {
	a, b := dotted("www.example.com."), dotted("example.com.")
	if !isSub(a, b) || isSub(b, a) || !isSub(a, "") || isSub(dotted("xexample.com."), b) {
		t.Fatal("isSub")
	}
	if parent(a) != b || labelCount(a) != 3 || ancestorAt(a, 1) != dotted("com.") || parent("") != "" {
		t.Fatal("labels")
	}
}

func TestMalformedNames(t *testing.T) {
	msg := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, name := range [][]byte{
		{0xC0, 12},     // points to itself
		{0xC0, 14},     // forward pointer
		{3, 'a', 'b'},  // runs past the end
		{0x40, 'a', 0}, // reserved label type
		append(bytes.Repeat([]byte{63}, 1), bytes.Repeat([]byte{'a'}, 63)...),
	} {
		if _, _, err := readName(append(slices.Clone(msg), name...), 12); err == nil {
			t.Errorf("accepted % x", name)
		}
	}
	long := []byte{}
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'a'}, 63)...)
	}
	if _, _, err := readName(append(append(slices.Clone(msg), long...), 0), 12); err == nil {
		t.Error("name longer than 255 bytes accepted")
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	soa := append(append([]byte(dotted("ns.example.com.")), 0), append([]byte(dotted("H.example.com.")), 0)...)
	soa = append(soa, make([]byte, 20)...)
	an := []rr{
		{name: dotted("www.example.com."), typ: m.TypeCNAME, class: 1, ttl: 60, data: append([]byte(dotted("Web.Example.com.")), 0)},
		{name: dotted("web.example.com."), typ: m.TypeA, class: 1, ttl: 60, data: []byte{192, 0, 2, 1}},
		{name: dotted("example.com."), typ: typeMX, class: 1, ttl: 60, data: append([]byte{0, 10}, append([]byte(dotted("mail.example.com.")), 0)...)},
	}
	ns := []rr{{name: dotted("example.com."), typ: m.TypeSOA, class: 1, ttl: 60, data: soa}}
	b := buildMessage(7, m.FlagQR, dotted("www.example.com."), m.TypeA, an, ns, nil, true, true, m.EDE(6, "x"))
	msg, err := parseMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.answer) != 3 || len(msg.authority) != 1 || !msg.edns || len(msg.ede) != 1 || msg.ede[0] != 6 {
		t.Fatalf("%+v", msg)
	}
	for i := range an {
		if !bytes.Equal(msg.answer[i].data, an[i].data) || msg.answer[i].name != an[i].name {
			t.Errorf("record %d: % x", i, msg.answer[i].data)
		}
	}
	if !bytes.Equal(msg.authority[0].data, soa) {
		t.Error("SOA changed")
	}
	// names were compressed
	if len(b) > 170 {
		t.Errorf("%d bytes: not compressed", len(b))
	}
	// the canonical form lowercases names inside record data
	if c := canonicalRdata(m.TypeCNAME, an[0].data); !bytes.Equal(c, append([]byte(dotted("web.example.com.")), 0)) {
		t.Errorf("canonical: %q", c)
	}
}

func TestTypeBitmap(t *testing.T) {
	// A, MX, RRSIG, NSEC and type 1234 (RFC 4034 4.3 style)
	bm := []byte{0, 6, 0x40, 0x01, 0, 0, 0, 0x03, 4, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20}
	for _, ty := range []uint16{1, 15, 46, 47, 1234} {
		if !typeBitmapHas(bm, ty) {
			t.Errorf("type %d missing", ty)
		}
	}
	for _, ty := range []uint16{2, 28, 43, 1235, 65535} {
		if typeBitmapHas(bm, ty) {
			t.Errorf("type %d present", ty)
		}
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(buildMessage(1, m.FlagQR, dotted("www.example.com."), 1,
		[]rr{{name: dotted("www.example.com."), typ: 1, class: 1, ttl: 5, data: []byte{1, 2, 3, 4}}}, nil, nil, true, true, nil))
	fx := loadFixture(f)
	for _, sets := range fx.sets {
		for _, s := range sets {
			f.Add(buildMessage(1, m.FlagQR, s.name, s.typ, append(s.records(), s.sigRecords(5)...), nil, nil, true, true, nil))
			break
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, err := parseMessage(b)
		if err != nil {
			return
		}
		sets := groupRRsets(append(append(msg.answer, msg.authority...), msg.additional...))
		budget := 4
		for _, s := range sets {
			canonicalRdata(s.typ, s.data[0])
			for _, raw := range s.sigs {
				parseSig(raw)
			}
			if s.typ == typeDNSKEY {
				for _, d := range s.data {
					if k, ok := parseKey(d); ok {
						verifySet(s, s.name, []*dnskey{k}, fx.now, &budget)
					}
				}
			}
		}
		proveNXDomainNSEC(nsecs(sets), msg.qname)
		proveNoDataNSEC(nsecs(sets), msg.qname, msg.qtype)
		if s, _ := nsec3sFor(sets, msg.qname); len(s.list) > 0 {
			proveNXDomainNSEC3(s, msg.qname)
			proveNoDataNSEC3(s, msg.qname, msg.qtype)
		}
		// what was parsed can be written and read back
		out := buildMessage(msg.id, msg.flags, msg.qname, msg.qtype, msg.answer, msg.authority, msg.additional, false, false, nil)
		again, err := parseMessage(out)
		if err != nil || len(again.answer) != len(msg.answer) || len(again.authority) != len(msg.authority) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
