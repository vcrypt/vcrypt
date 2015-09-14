package config

//go:generate peg -switch -inline parser.peg

type section struct {
	Type, ID string
	Values   map[string][]string
}

func parse(data []byte) ([]*section, error) {
	p := &parser{
		Buffer: string(data),
	}

	p.Init()
	p.addSection("")

	if err := p.Parse(); err != nil {
		return nil, err
	}
	p.Execute()

	return p.sections, nil
}

func (p *parser) addSection(stype string) {
	p.curSection = &section{
		Type:   stype,
		Values: make(map[string][]string),
	}
	p.sections = append(p.sections, p.curSection)
}

func (p *parser) setID(id string) {
	p.curSection.ID = id
}

func (p *parser) setKey(key string) {
	p.curKey = key
}

func (p *parser) addValue(value string) {
	p.curSection.Values[p.curKey] = append(p.curSection.Values[p.curKey], value)
}
