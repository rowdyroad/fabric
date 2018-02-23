package hellgost

type Sign struct {
	Key     string
	Data    []byte
	Marshal bool
}

type Verify struct {
	Key  string
	Data []byte
	Sign []byte
}

type Hash struct {
	Data []byte
}

type GenKey struct {
	Key string
}

type Void struct {
}
