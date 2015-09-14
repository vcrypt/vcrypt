package config

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

const end_symbol rune = 1114112

/* The rule types inferred from the grammar are below. */
type pegRule uint8

const (
	ruleUnknown pegRule = iota
	ruleGrammar
	ruleRootSection
	ruleSection
	ruleValueLine
	ruleValue
	ruleValueMultiLine
	ruleQuotedIdentifier
	ruleIdentifier
	ruleWord
	ruleSpaceComment
	ruleComment
	ruleSpace
	ruleEndOfLine
	rulePegText
	ruleAction0
	ruleAction1
	ruleAction2
	ruleAction3
	ruleAction4
	ruleAction5

	rulePre_
	rule_In_
	rule_Suf
)

var rul3s = [...]string{
	"Unknown",
	"Grammar",
	"RootSection",
	"Section",
	"ValueLine",
	"Value",
	"ValueMultiLine",
	"QuotedIdentifier",
	"Identifier",
	"Word",
	"SpaceComment",
	"Comment",
	"Space",
	"EndOfLine",
	"PegText",
	"Action0",
	"Action1",
	"Action2",
	"Action3",
	"Action4",
	"Action5",

	"Pre_",
	"_In_",
	"_Suf",
}

type tokenTree interface {
	Print()
	PrintSyntax()
	PrintSyntaxTree(buffer string)
	Add(rule pegRule, begin, end, next uint32, depth int)
	Expand(index int) tokenTree
	Tokens() <-chan token32
	AST() *node32
	Error() []token32
	trim(length int)
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(depth int, buffer string) {
	for node != nil {
		for c := 0; c < depth; c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[node.pegRule], strconv.Quote(string(([]rune(buffer)[node.begin:node.end]))))
		if node.up != nil {
			node.up.print(depth+1, buffer)
		}
		node = node.next
	}
}

func (ast *node32) Print(buffer string) {
	ast.print(0, buffer)
}

type element struct {
	node *node32
	down *element
}

/* ${@} bit structure for abstract syntax tree */
type token32 struct {
	pegRule
	begin, end, next uint32
}

func (t *token32) isZero() bool {
	return t.pegRule == ruleUnknown && t.begin == 0 && t.end == 0 && t.next == 0
}

func (t *token32) isParentOf(u token32) bool {
	return t.begin <= u.begin && t.end >= u.end && t.next > u.next
}

func (t *token32) getToken32() token32 {
	return token32{pegRule: t.pegRule, begin: uint32(t.begin), end: uint32(t.end), next: uint32(t.next)}
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v %v", rul3s[t.pegRule], t.begin, t.end, t.next)
}

type tokens32 struct {
	tree    []token32
	ordered [][]token32
}

func (t *tokens32) trim(length int) {
	t.tree = t.tree[0:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) Order() [][]token32 {
	if t.ordered != nil {
		return t.ordered
	}

	depths := make([]int32, 1, math.MaxInt16)
	for i, token := range t.tree {
		if token.pegRule == ruleUnknown {
			t.tree = t.tree[:i]
			break
		}
		depth := int(token.next)
		if length := len(depths); depth >= length {
			depths = depths[:depth+1]
		}
		depths[depth]++
	}
	depths = append(depths, 0)

	ordered, pool := make([][]token32, len(depths)), make([]token32, len(t.tree)+len(depths))
	for i, depth := range depths {
		depth++
		ordered[i], pool, depths[i] = pool[:depth], pool[depth:], 0
	}

	for i, token := range t.tree {
		depth := token.next
		token.next = uint32(i)
		ordered[depth][depths[depth]] = token
		depths[depth]++
	}
	t.ordered = ordered
	return ordered
}

type state32 struct {
	token32
	depths []int32
	leaf   bool
}

func (t *tokens32) AST() *node32 {
	tokens := t.Tokens()
	stack := &element{node: &node32{token32: <-tokens}}
	for token := range tokens {
		if token.begin == token.end {
			continue
		}
		node := &node32{token32: token}
		for stack != nil && stack.node.begin >= token.begin && stack.node.end <= token.end {
			stack.node.next = node.up
			node.up = stack.node
			stack = stack.down
		}
		stack = &element{node: node, down: stack}
	}
	return stack.node
}

func (t *tokens32) PreOrder() (<-chan state32, [][]token32) {
	s, ordered := make(chan state32, 6), t.Order()
	go func() {
		var states [8]state32
		for i, _ := range states {
			states[i].depths = make([]int32, len(ordered))
		}
		depths, state, depth := make([]int32, len(ordered)), 0, 1
		write := func(t token32, leaf bool) {
			S := states[state]
			state, S.pegRule, S.begin, S.end, S.next, S.leaf = (state+1)%8, t.pegRule, t.begin, t.end, uint32(depth), leaf
			copy(S.depths, depths)
			s <- S
		}

		states[state].token32 = ordered[0][0]
		depths[0]++
		state++
		a, b := ordered[depth-1][depths[depth-1]-1], ordered[depth][depths[depth]]
	depthFirstSearch:
		for {
			for {
				if i := depths[depth]; i > 0 {
					if c, j := ordered[depth][i-1], depths[depth-1]; a.isParentOf(c) &&
						(j < 2 || !ordered[depth-1][j-2].isParentOf(c)) {
						if c.end != b.begin {
							write(token32{pegRule: rule_In_, begin: c.end, end: b.begin}, true)
						}
						break
					}
				}

				if a.begin < b.begin {
					write(token32{pegRule: rulePre_, begin: a.begin, end: b.begin}, true)
				}
				break
			}

			next := depth + 1
			if c := ordered[next][depths[next]]; c.pegRule != ruleUnknown && b.isParentOf(c) {
				write(b, false)
				depths[depth]++
				depth, a, b = next, b, c
				continue
			}

			write(b, true)
			depths[depth]++
			c, parent := ordered[depth][depths[depth]], true
			for {
				if c.pegRule != ruleUnknown && a.isParentOf(c) {
					b = c
					continue depthFirstSearch
				} else if parent && b.end != a.end {
					write(token32{pegRule: rule_Suf, begin: b.end, end: a.end}, true)
				}

				depth--
				if depth > 0 {
					a, b, c = ordered[depth-1][depths[depth-1]-1], a, ordered[depth][depths[depth]]
					parent = a.isParentOf(b)
					continue
				}

				break depthFirstSearch
			}
		}

		close(s)
	}()
	return s, ordered
}

func (t *tokens32) PrintSyntax() {
	tokens, ordered := t.PreOrder()
	max := -1
	for token := range tokens {
		if !token.leaf {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[36m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[36m%v\x1B[m\n", rul3s[token.pegRule])
		} else if token.begin == token.end {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[31m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[31m%v\x1B[m\n", rul3s[token.pegRule])
		} else {
			for c, end := token.begin, token.end; c < end; c++ {
				if i := int(c); max+1 < i {
					for j := max; j < i; j++ {
						fmt.Printf("skip %v %v\n", j, token.String())
					}
					max = i
				} else if i := int(c); i <= max {
					for j := i; j <= max; j++ {
						fmt.Printf("dupe %v %v\n", j, token.String())
					}
				} else {
					max = int(c)
				}
				fmt.Printf("%v", c)
				for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
					fmt.Printf(" \x1B[34m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
				}
				fmt.Printf(" \x1B[34m%v\x1B[m\n", rul3s[token.pegRule])
			}
			fmt.Printf("\n")
		}
	}
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	tokens, _ := t.PreOrder()
	for token := range tokens {
		for c := 0; c < int(token.next); c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[token.pegRule], strconv.Quote(string(([]rune(buffer)[token.begin:token.end]))))
	}
}

func (t *tokens32) Add(rule pegRule, begin, end, depth uint32, index int) {
	t.tree[index] = token32{pegRule: rule, begin: uint32(begin), end: uint32(end), next: uint32(depth)}
}

func (t *tokens32) Tokens() <-chan token32 {
	s := make(chan token32, 16)
	go func() {
		for _, v := range t.tree {
			s <- v.getToken32()
		}
		close(s)
	}()
	return s
}

func (t *tokens32) Error() []token32 {
	ordered := t.Order()
	length := len(ordered)
	tokens, length := make([]token32, length), length-1
	for i, _ := range tokens {
		o := ordered[length-i]
		if len(o) > 1 {
			tokens[i] = o[len(o)-2].getToken32()
		}
	}
	return tokens
}

/*func (t *tokens16) Expand(index int) tokenTree {
	tree := t.tree
	if index >= len(tree) {
		expanded := make([]token32, 2 * len(tree))
		for i, v := range tree {
			expanded[i] = v.getToken32()
		}
		return &tokens32{tree: expanded}
	}
	return nil
}*/

func (t *tokens32) Expand(index int) tokenTree {
	tree := t.tree
	if index >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
	return nil
}

type parser struct {
	sections []*section

	curSection *section
	curKey     string

	Buffer string
	buffer []rune
	rules  [21]func() bool
	Parse  func(rule ...int) error
	Reset  func()
	tokenTree
}

type textPosition struct {
	line, symbol int
}

type textPositionMap map[int]textPosition

func translatePositions(buffer string, positions []int) textPositionMap {
	length, translations, j, line, symbol := len(positions), make(textPositionMap, len(positions)), 0, 1, 0
	sort.Ints(positions)

search:
	for i, c := range []rune(buffer) {
		if c == '\n' {
			line, symbol = line+1, 0
		} else {
			symbol++
		}
		if i == positions[j] {
			translations[positions[j]] = textPosition{line, symbol}
			for j++; j < length; j++ {
				if i != positions[j] {
					continue search
				}
			}
			break search
		}
	}

	return translations
}

type parseError struct {
	p *parser
}

func (e *parseError) Error() string {
	tokens, error := e.p.tokenTree.Error(), "\n"
	positions, p := make([]int, 2*len(tokens)), 0
	for _, token := range tokens {
		positions[p], p = int(token.begin), p+1
		positions[p], p = int(token.end), p+1
	}
	translations := translatePositions(e.p.Buffer, positions)
	for _, token := range tokens {
		begin, end := int(token.begin), int(token.end)
		error += fmt.Sprintf("parse error near \x1B[34m%v\x1B[m (line %v symbol %v - line %v symbol %v):\n%v\n",
			rul3s[token.pegRule],
			translations[begin].line, translations[begin].symbol,
			translations[end].line, translations[end].symbol,
			/*strconv.Quote(*/ e.p.Buffer[begin:end] /*)*/)
	}

	return error
}

func (p *parser) PrintSyntaxTree() {
	p.tokenTree.PrintSyntaxTree(p.Buffer)
}

func (p *parser) Highlighter() {
	p.tokenTree.PrintSyntax()
}

func (p *parser) Execute() {
	buffer, _buffer, text, begin, end := p.Buffer, p.buffer, "", 0, 0
	for token := range p.tokenTree.Tokens() {
		switch token.pegRule {

		case rulePegText:
			begin, end = int(token.begin), int(token.end)
			text = string(_buffer[begin:end])

		case ruleAction0:
			p.addSection(text)
		case ruleAction1:
			p.setID(text)
		case ruleAction2:
			p.setKey(text)
		case ruleAction3:
			p.addValue(text)
		case ruleAction4:
			p.setKey(text)
		case ruleAction5:
			p.addValue(text)

		}
	}
	_, _, _, _, _ = buffer, _buffer, text, begin, end
}

func (p *parser) Init() {
	p.buffer = []rune(p.Buffer)
	if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != end_symbol {
		p.buffer = append(p.buffer, end_symbol)
	}

	var tree tokenTree = &tokens32{tree: make([]token32, math.MaxInt16)}
	position, depth, tokenIndex, buffer, _rules := uint32(0), uint32(0), 0, p.buffer, p.rules

	p.Parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokenTree = tree
		if matches {
			p.tokenTree.trim(tokenIndex)
			return nil
		}
		return &parseError{p}
	}

	p.Reset = func() {
		position, tokenIndex, depth = 0, 0, 0
	}

	add := func(rule pegRule, begin uint32) {
		if t := tree.Expand(tokenIndex); t != nil {
			tree = t
		}
		tree.Add(rule, begin, position, depth, tokenIndex)
		tokenIndex++
	}

	matchDot := func() bool {
		if buffer[position] != end_symbol {
			position++
			return true
		}
		return false
	}

	/*matchChar := func(c byte) bool {
		if buffer[position] == c {
			position++
			return true
		}
		return false
	}*/

	/*matchRange := func(lower byte, upper byte) bool {
		if c := buffer[position]; c >= lower && c <= upper {
			position++
			return true
		}
		return false
	}*/

	_rules = [...]func() bool{
		nil,
		/* 0 Grammar <- <(RootSection? (SpaceComment / Section)+)> */
		func() bool {
			position0, tokenIndex0, depth0 := position, tokenIndex, depth
			{
				position1 := position
				depth++
				{
					position2, tokenIndex2, depth2 := position, tokenIndex, depth
					{
						position4 := position
						depth++
					l5:
						{
							position6, tokenIndex6, depth6 := position, tokenIndex, depth
							if !_rules[ruleSpaceComment]() {
								goto l6
							}
							goto l5
						l6:
							position, tokenIndex, depth = position6, tokenIndex6, depth6
						}
						if !_rules[ruleValueLine]() {
							goto l2
						}
					l7:
						{
							position8, tokenIndex8, depth8 := position, tokenIndex, depth
							if !_rules[ruleValueLine]() {
								goto l8
							}
							goto l7
						l8:
							position, tokenIndex, depth = position8, tokenIndex8, depth8
						}
						depth--
						add(ruleRootSection, position4)
					}
					goto l3
				l2:
					position, tokenIndex, depth = position2, tokenIndex2, depth2
				}
			l3:
				{
					position11, tokenIndex11, depth11 := position, tokenIndex, depth
					if !_rules[ruleSpaceComment]() {
						goto l12
					}
					goto l11
				l12:
					position, tokenIndex, depth = position11, tokenIndex11, depth11
					{
						position13 := position
						depth++
					l14:
						{
							position15, tokenIndex15, depth15 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l15
							}
							goto l14
						l15:
							position, tokenIndex, depth = position15, tokenIndex15, depth15
						}
						if buffer[position] != rune('[') {
							goto l0
						}
						position++
					l16:
						{
							position17, tokenIndex17, depth17 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l17
							}
							goto l16
						l17:
							position, tokenIndex, depth = position17, tokenIndex17, depth17
						}
						{
							position18 := position
							depth++
							if !_rules[ruleIdentifier]() {
								goto l0
							}
							depth--
							add(rulePegText, position18)
						}
						{
							add(ruleAction0, position)
						}
						{
							position20, tokenIndex20, depth20 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l20
							}
						l22:
							{
								position23, tokenIndex23, depth23 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l23
								}
								goto l22
							l23:
								position, tokenIndex, depth = position23, tokenIndex23, depth23
							}
							if buffer[position] != rune('"') {
								goto l20
							}
							position++
							{
								position24 := position
								depth++
								{
									position25 := position
									depth++
									{
										switch buffer[position] {
										case ' ':
											if buffer[position] != rune(' ') {
												goto l20
											}
											position++
											break
										case '.':
											if buffer[position] != rune('.') {
												goto l20
											}
											position++
											break
										case '@':
											if buffer[position] != rune('@') {
												goto l20
											}
											position++
											break
										case '-':
											if buffer[position] != rune('-') {
												goto l20
											}
											position++
											break
										case '_':
											if buffer[position] != rune('_') {
												goto l20
											}
											position++
											break
										case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
											{
												position29, tokenIndex29, depth29 := position, tokenIndex, depth
												if c := buffer[position]; c < rune('0') || c > rune('9') {
													goto l30
												}
												position++
												goto l29
											l30:
												position, tokenIndex, depth = position29, tokenIndex29, depth29
												if c := buffer[position]; c < rune('0') || c > rune('9') {
													goto l20
												}
												position++
											}
										l29:
											break
										case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
											if c := buffer[position]; c < rune('A') || c > rune('Z') {
												goto l20
											}
											position++
											break
										default:
											if c := buffer[position]; c < rune('a') || c > rune('z') {
												goto l20
											}
											position++
											break
										}
									}

								l26:
									{
										position27, tokenIndex27, depth27 := position, tokenIndex, depth
										{
											switch buffer[position] {
											case ' ':
												if buffer[position] != rune(' ') {
													goto l27
												}
												position++
												break
											case '.':
												if buffer[position] != rune('.') {
													goto l27
												}
												position++
												break
											case '@':
												if buffer[position] != rune('@') {
													goto l27
												}
												position++
												break
											case '-':
												if buffer[position] != rune('-') {
													goto l27
												}
												position++
												break
											case '_':
												if buffer[position] != rune('_') {
													goto l27
												}
												position++
												break
											case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
												{
													position32, tokenIndex32, depth32 := position, tokenIndex, depth
													if c := buffer[position]; c < rune('0') || c > rune('9') {
														goto l33
													}
													position++
													goto l32
												l33:
													position, tokenIndex, depth = position32, tokenIndex32, depth32
													if c := buffer[position]; c < rune('0') || c > rune('9') {
														goto l27
													}
													position++
												}
											l32:
												break
											case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
												if c := buffer[position]; c < rune('A') || c > rune('Z') {
													goto l27
												}
												position++
												break
											default:
												if c := buffer[position]; c < rune('a') || c > rune('z') {
													goto l27
												}
												position++
												break
											}
										}

										goto l26
									l27:
										position, tokenIndex, depth = position27, tokenIndex27, depth27
									}
									depth--
									add(ruleQuotedIdentifier, position25)
								}
								depth--
								add(rulePegText, position24)
							}
							{
								add(ruleAction1, position)
							}
							if buffer[position] != rune('"') {
								goto l20
							}
							position++
							goto l21
						l20:
							position, tokenIndex, depth = position20, tokenIndex20, depth20
						}
					l21:
					l35:
						{
							position36, tokenIndex36, depth36 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l36
							}
							goto l35
						l36:
							position, tokenIndex, depth = position36, tokenIndex36, depth36
						}
						if buffer[position] != rune(']') {
							goto l0
						}
						position++
						if !_rules[ruleSpaceComment]() {
							goto l0
						}
					l37:
						{
							position38, tokenIndex38, depth38 := position, tokenIndex, depth
							{
								position39, tokenIndex39, depth39 := position, tokenIndex, depth
								if !_rules[ruleValueLine]() {
									goto l40
								}
								goto l39
							l40:
								position, tokenIndex, depth = position39, tokenIndex39, depth39
								{
									position41 := position
									depth++
								l42:
									{
										position43, tokenIndex43, depth43 := position, tokenIndex, depth
										if !_rules[ruleSpace]() {
											goto l43
										}
										goto l42
									l43:
										position, tokenIndex, depth = position43, tokenIndex43, depth43
									}
									{
										position44 := position
										depth++
										if !_rules[ruleIdentifier]() {
											goto l38
										}
										depth--
										add(rulePegText, position44)
									}
									{
										add(ruleAction4, position)
									}
								l46:
									{
										position47, tokenIndex47, depth47 := position, tokenIndex, depth
										if !_rules[ruleSpace]() {
											goto l47
										}
										goto l46
									l47:
										position, tokenIndex, depth = position47, tokenIndex47, depth47
									}
									if buffer[position] != rune('=') {
										goto l38
									}
									position++
								l48:
									{
										position49, tokenIndex49, depth49 := position, tokenIndex, depth
										if !_rules[ruleSpace]() {
											goto l49
										}
										goto l48
									l49:
										position, tokenIndex, depth = position49, tokenIndex49, depth49
									}
									if buffer[position] != rune('"') {
										goto l38
									}
									position++
									{
										position50 := position
										depth++
										{
											position53, tokenIndex53, depth53 := position, tokenIndex, depth
											if buffer[position] != rune('"') {
												goto l53
											}
											position++
											goto l38
										l53:
											position, tokenIndex, depth = position53, tokenIndex53, depth53
										}
										if !matchDot() {
											goto l38
										}
									l51:
										{
											position52, tokenIndex52, depth52 := position, tokenIndex, depth
											{
												position54, tokenIndex54, depth54 := position, tokenIndex, depth
												if buffer[position] != rune('"') {
													goto l54
												}
												position++
												goto l52
											l54:
												position, tokenIndex, depth = position54, tokenIndex54, depth54
											}
											if !matchDot() {
												goto l52
											}
											goto l51
										l52:
											position, tokenIndex, depth = position52, tokenIndex52, depth52
										}
										depth--
										add(rulePegText, position50)
									}
									{
										add(ruleAction5, position)
									}
									if buffer[position] != rune('"') {
										goto l38
									}
									position++
									if !_rules[ruleSpaceComment]() {
										goto l38
									}
									depth--
									add(ruleValueMultiLine, position41)
								}
							}
						l39:
							goto l37
						l38:
							position, tokenIndex, depth = position38, tokenIndex38, depth38
						}
						depth--
						add(ruleSection, position13)
					}
				}
			l11:
			l9:
				{
					position10, tokenIndex10, depth10 := position, tokenIndex, depth
					{
						position56, tokenIndex56, depth56 := position, tokenIndex, depth
						if !_rules[ruleSpaceComment]() {
							goto l57
						}
						goto l56
					l57:
						position, tokenIndex, depth = position56, tokenIndex56, depth56
						{
							position58 := position
							depth++
						l59:
							{
								position60, tokenIndex60, depth60 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l60
								}
								goto l59
							l60:
								position, tokenIndex, depth = position60, tokenIndex60, depth60
							}
							if buffer[position] != rune('[') {
								goto l10
							}
							position++
						l61:
							{
								position62, tokenIndex62, depth62 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l62
								}
								goto l61
							l62:
								position, tokenIndex, depth = position62, tokenIndex62, depth62
							}
							{
								position63 := position
								depth++
								if !_rules[ruleIdentifier]() {
									goto l10
								}
								depth--
								add(rulePegText, position63)
							}
							{
								add(ruleAction0, position)
							}
							{
								position65, tokenIndex65, depth65 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l65
								}
							l67:
								{
									position68, tokenIndex68, depth68 := position, tokenIndex, depth
									if !_rules[ruleSpace]() {
										goto l68
									}
									goto l67
								l68:
									position, tokenIndex, depth = position68, tokenIndex68, depth68
								}
								if buffer[position] != rune('"') {
									goto l65
								}
								position++
								{
									position69 := position
									depth++
									{
										position70 := position
										depth++
										{
											switch buffer[position] {
											case ' ':
												if buffer[position] != rune(' ') {
													goto l65
												}
												position++
												break
											case '.':
												if buffer[position] != rune('.') {
													goto l65
												}
												position++
												break
											case '@':
												if buffer[position] != rune('@') {
													goto l65
												}
												position++
												break
											case '-':
												if buffer[position] != rune('-') {
													goto l65
												}
												position++
												break
											case '_':
												if buffer[position] != rune('_') {
													goto l65
												}
												position++
												break
											case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
												{
													position74, tokenIndex74, depth74 := position, tokenIndex, depth
													if c := buffer[position]; c < rune('0') || c > rune('9') {
														goto l75
													}
													position++
													goto l74
												l75:
													position, tokenIndex, depth = position74, tokenIndex74, depth74
													if c := buffer[position]; c < rune('0') || c > rune('9') {
														goto l65
													}
													position++
												}
											l74:
												break
											case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
												if c := buffer[position]; c < rune('A') || c > rune('Z') {
													goto l65
												}
												position++
												break
											default:
												if c := buffer[position]; c < rune('a') || c > rune('z') {
													goto l65
												}
												position++
												break
											}
										}

									l71:
										{
											position72, tokenIndex72, depth72 := position, tokenIndex, depth
											{
												switch buffer[position] {
												case ' ':
													if buffer[position] != rune(' ') {
														goto l72
													}
													position++
													break
												case '.':
													if buffer[position] != rune('.') {
														goto l72
													}
													position++
													break
												case '@':
													if buffer[position] != rune('@') {
														goto l72
													}
													position++
													break
												case '-':
													if buffer[position] != rune('-') {
														goto l72
													}
													position++
													break
												case '_':
													if buffer[position] != rune('_') {
														goto l72
													}
													position++
													break
												case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
													{
														position77, tokenIndex77, depth77 := position, tokenIndex, depth
														if c := buffer[position]; c < rune('0') || c > rune('9') {
															goto l78
														}
														position++
														goto l77
													l78:
														position, tokenIndex, depth = position77, tokenIndex77, depth77
														if c := buffer[position]; c < rune('0') || c > rune('9') {
															goto l72
														}
														position++
													}
												l77:
													break
												case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
													if c := buffer[position]; c < rune('A') || c > rune('Z') {
														goto l72
													}
													position++
													break
												default:
													if c := buffer[position]; c < rune('a') || c > rune('z') {
														goto l72
													}
													position++
													break
												}
											}

											goto l71
										l72:
											position, tokenIndex, depth = position72, tokenIndex72, depth72
										}
										depth--
										add(ruleQuotedIdentifier, position70)
									}
									depth--
									add(rulePegText, position69)
								}
								{
									add(ruleAction1, position)
								}
								if buffer[position] != rune('"') {
									goto l65
								}
								position++
								goto l66
							l65:
								position, tokenIndex, depth = position65, tokenIndex65, depth65
							}
						l66:
						l80:
							{
								position81, tokenIndex81, depth81 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l81
								}
								goto l80
							l81:
								position, tokenIndex, depth = position81, tokenIndex81, depth81
							}
							if buffer[position] != rune(']') {
								goto l10
							}
							position++
							if !_rules[ruleSpaceComment]() {
								goto l10
							}
						l82:
							{
								position83, tokenIndex83, depth83 := position, tokenIndex, depth
								{
									position84, tokenIndex84, depth84 := position, tokenIndex, depth
									if !_rules[ruleValueLine]() {
										goto l85
									}
									goto l84
								l85:
									position, tokenIndex, depth = position84, tokenIndex84, depth84
									{
										position86 := position
										depth++
									l87:
										{
											position88, tokenIndex88, depth88 := position, tokenIndex, depth
											if !_rules[ruleSpace]() {
												goto l88
											}
											goto l87
										l88:
											position, tokenIndex, depth = position88, tokenIndex88, depth88
										}
										{
											position89 := position
											depth++
											if !_rules[ruleIdentifier]() {
												goto l83
											}
											depth--
											add(rulePegText, position89)
										}
										{
											add(ruleAction4, position)
										}
									l91:
										{
											position92, tokenIndex92, depth92 := position, tokenIndex, depth
											if !_rules[ruleSpace]() {
												goto l92
											}
											goto l91
										l92:
											position, tokenIndex, depth = position92, tokenIndex92, depth92
										}
										if buffer[position] != rune('=') {
											goto l83
										}
										position++
									l93:
										{
											position94, tokenIndex94, depth94 := position, tokenIndex, depth
											if !_rules[ruleSpace]() {
												goto l94
											}
											goto l93
										l94:
											position, tokenIndex, depth = position94, tokenIndex94, depth94
										}
										if buffer[position] != rune('"') {
											goto l83
										}
										position++
										{
											position95 := position
											depth++
											{
												position98, tokenIndex98, depth98 := position, tokenIndex, depth
												if buffer[position] != rune('"') {
													goto l98
												}
												position++
												goto l83
											l98:
												position, tokenIndex, depth = position98, tokenIndex98, depth98
											}
											if !matchDot() {
												goto l83
											}
										l96:
											{
												position97, tokenIndex97, depth97 := position, tokenIndex, depth
												{
													position99, tokenIndex99, depth99 := position, tokenIndex, depth
													if buffer[position] != rune('"') {
														goto l99
													}
													position++
													goto l97
												l99:
													position, tokenIndex, depth = position99, tokenIndex99, depth99
												}
												if !matchDot() {
													goto l97
												}
												goto l96
											l97:
												position, tokenIndex, depth = position97, tokenIndex97, depth97
											}
											depth--
											add(rulePegText, position95)
										}
										{
											add(ruleAction5, position)
										}
										if buffer[position] != rune('"') {
											goto l83
										}
										position++
										if !_rules[ruleSpaceComment]() {
											goto l83
										}
										depth--
										add(ruleValueMultiLine, position86)
									}
								}
							l84:
								goto l82
							l83:
								position, tokenIndex, depth = position83, tokenIndex83, depth83
							}
							depth--
							add(ruleSection, position58)
						}
					}
				l56:
					goto l9
				l10:
					position, tokenIndex, depth = position10, tokenIndex10, depth10
				}
				depth--
				add(ruleGrammar, position1)
			}
			return true
		l0:
			position, tokenIndex, depth = position0, tokenIndex0, depth0
			return false
		},
		/* 1 RootSection <- <(SpaceComment* ValueLine+)> */
		nil,
		/* 2 Section <- <(Space* '[' Space* <Identifier> Action0 (Space+ '"' <QuotedIdentifier> Action1 '"')? Space* ']' SpaceComment (ValueLine / ValueMultiLine)*)> */
		nil,
		/* 3 ValueLine <- <(Space* <Identifier> Action2 Space* '=' Space* <Value> Action3 SpaceComment)> */
		func() bool {
			position103, tokenIndex103, depth103 := position, tokenIndex, depth
			{
				position104 := position
				depth++
			l105:
				{
					position106, tokenIndex106, depth106 := position, tokenIndex, depth
					if !_rules[ruleSpace]() {
						goto l106
					}
					goto l105
				l106:
					position, tokenIndex, depth = position106, tokenIndex106, depth106
				}
				{
					position107 := position
					depth++
					if !_rules[ruleIdentifier]() {
						goto l103
					}
					depth--
					add(rulePegText, position107)
				}
				{
					add(ruleAction2, position)
				}
			l109:
				{
					position110, tokenIndex110, depth110 := position, tokenIndex, depth
					if !_rules[ruleSpace]() {
						goto l110
					}
					goto l109
				l110:
					position, tokenIndex, depth = position110, tokenIndex110, depth110
				}
				if buffer[position] != rune('=') {
					goto l103
				}
				position++
			l111:
				{
					position112, tokenIndex112, depth112 := position, tokenIndex, depth
					if !_rules[ruleSpace]() {
						goto l112
					}
					goto l111
				l112:
					position, tokenIndex, depth = position112, tokenIndex112, depth112
				}
				{
					position113 := position
					depth++
					{
						position114 := position
						depth++
						if !_rules[ruleWord]() {
							goto l103
						}
					l115:
						{
							position116, tokenIndex116, depth116 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l116
							}
						l117:
							{
								position118, tokenIndex118, depth118 := position, tokenIndex, depth
								if !_rules[ruleSpace]() {
									goto l118
								}
								goto l117
							l118:
								position, tokenIndex, depth = position118, tokenIndex118, depth118
							}
							if !_rules[ruleWord]() {
								goto l116
							}
							goto l115
						l116:
							position, tokenIndex, depth = position116, tokenIndex116, depth116
						}
						depth--
						add(ruleValue, position114)
					}
					depth--
					add(rulePegText, position113)
				}
				{
					add(ruleAction3, position)
				}
				if !_rules[ruleSpaceComment]() {
					goto l103
				}
				depth--
				add(ruleValueLine, position104)
			}
			return true
		l103:
			position, tokenIndex, depth = position103, tokenIndex103, depth103
			return false
		},
		/* 4 Value <- <(Word (Space+ Word)*)> */
		nil,
		/* 5 ValueMultiLine <- <(Space* <Identifier> Action4 Space* '=' Space* '"' <(!'"' .)+> Action5 '"' SpaceComment)> */
		nil,
		/* 6 QuotedIdentifier <- <((&(' ') ' ') | (&('.') '.') | (&('@') '@') | (&('-') '-') | (&('_') '_') | (&('0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9') ([0-9] / [0-9])) | (&('A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z') [A-Z]) | (&('a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z') [a-z]))+> */
		nil,
		/* 7 Identifier <- <((&('.') '.') | (&('@') '@') | (&('-') '-') | (&('_') '_') | (&('0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9') ([0-9] / [0-9])) | (&('A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z') [A-Z]) | (&('a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z') [a-z]))+> */
		func() bool {
			position123, tokenIndex123, depth123 := position, tokenIndex, depth
			{
				position124 := position
				depth++
				{
					switch buffer[position] {
					case '.':
						if buffer[position] != rune('.') {
							goto l123
						}
						position++
						break
					case '@':
						if buffer[position] != rune('@') {
							goto l123
						}
						position++
						break
					case '-':
						if buffer[position] != rune('-') {
							goto l123
						}
						position++
						break
					case '_':
						if buffer[position] != rune('_') {
							goto l123
						}
						position++
						break
					case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
						{
							position128, tokenIndex128, depth128 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l129
							}
							position++
							goto l128
						l129:
							position, tokenIndex, depth = position128, tokenIndex128, depth128
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l123
							}
							position++
						}
					l128:
						break
					case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l123
						}
						position++
						break
					default:
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l123
						}
						position++
						break
					}
				}

			l125:
				{
					position126, tokenIndex126, depth126 := position, tokenIndex, depth
					{
						switch buffer[position] {
						case '.':
							if buffer[position] != rune('.') {
								goto l126
							}
							position++
							break
						case '@':
							if buffer[position] != rune('@') {
								goto l126
							}
							position++
							break
						case '-':
							if buffer[position] != rune('-') {
								goto l126
							}
							position++
							break
						case '_':
							if buffer[position] != rune('_') {
								goto l126
							}
							position++
							break
						case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
							{
								position131, tokenIndex131, depth131 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l132
								}
								position++
								goto l131
							l132:
								position, tokenIndex, depth = position131, tokenIndex131, depth131
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l126
								}
								position++
							}
						l131:
							break
						case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l126
							}
							position++
							break
						default:
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l126
							}
							position++
							break
						}
					}

					goto l125
				l126:
					position, tokenIndex, depth = position126, tokenIndex126, depth126
				}
				depth--
				add(ruleIdentifier, position124)
			}
			return true
		l123:
			position, tokenIndex, depth = position123, tokenIndex123, depth123
			return false
		},
		/* 8 Word <- <(!((&('\n') '\n') | (&('\r') '\r') | (&('#') '#') | (&('\t') '\t') | (&('"') '"') | (&(' ') ' ')) .)+> */
		func() bool {
			position133, tokenIndex133, depth133 := position, tokenIndex, depth
			{
				position134 := position
				depth++
				{
					position137, tokenIndex137, depth137 := position, tokenIndex, depth
					{
						switch buffer[position] {
						case '\n':
							if buffer[position] != rune('\n') {
								goto l137
							}
							position++
							break
						case '\r':
							if buffer[position] != rune('\r') {
								goto l137
							}
							position++
							break
						case '#':
							if buffer[position] != rune('#') {
								goto l137
							}
							position++
							break
						case '\t':
							if buffer[position] != rune('\t') {
								goto l137
							}
							position++
							break
						case '"':
							if buffer[position] != rune('"') {
								goto l137
							}
							position++
							break
						default:
							if buffer[position] != rune(' ') {
								goto l137
							}
							position++
							break
						}
					}

					goto l133
				l137:
					position, tokenIndex, depth = position137, tokenIndex137, depth137
				}
				if !matchDot() {
					goto l133
				}
			l135:
				{
					position136, tokenIndex136, depth136 := position, tokenIndex, depth
					{
						position139, tokenIndex139, depth139 := position, tokenIndex, depth
						{
							switch buffer[position] {
							case '\n':
								if buffer[position] != rune('\n') {
									goto l139
								}
								position++
								break
							case '\r':
								if buffer[position] != rune('\r') {
									goto l139
								}
								position++
								break
							case '#':
								if buffer[position] != rune('#') {
									goto l139
								}
								position++
								break
							case '\t':
								if buffer[position] != rune('\t') {
									goto l139
								}
								position++
								break
							case '"':
								if buffer[position] != rune('"') {
									goto l139
								}
								position++
								break
							default:
								if buffer[position] != rune(' ') {
									goto l139
								}
								position++
								break
							}
						}

						goto l136
					l139:
						position, tokenIndex, depth = position139, tokenIndex139, depth139
					}
					if !matchDot() {
						goto l136
					}
					goto l135
				l136:
					position, tokenIndex, depth = position136, tokenIndex136, depth136
				}
				depth--
				add(ruleWord, position134)
			}
			return true
		l133:
			position, tokenIndex, depth = position133, tokenIndex133, depth133
			return false
		},
		/* 9 SpaceComment <- <((&('\n' | '\r') EndOfLine) | (&('#') Comment) | (&('\t' | ' ') Space+))> */
		func() bool {
			position141, tokenIndex141, depth141 := position, tokenIndex, depth
			{
				position142 := position
				depth++
				{
					switch buffer[position] {
					case '\n', '\r':
						if !_rules[ruleEndOfLine]() {
							goto l141
						}
						break
					case '#':
						{
							position144 := position
							depth++
							if buffer[position] != rune('#') {
								goto l141
							}
							position++
						l145:
							{
								position146, tokenIndex146, depth146 := position, tokenIndex, depth
								{
									position147, tokenIndex147, depth147 := position, tokenIndex, depth
									if !_rules[ruleEndOfLine]() {
										goto l147
									}
									goto l146
								l147:
									position, tokenIndex, depth = position147, tokenIndex147, depth147
								}
								if !matchDot() {
									goto l146
								}
								goto l145
							l146:
								position, tokenIndex, depth = position146, tokenIndex146, depth146
							}
							if !_rules[ruleEndOfLine]() {
								goto l141
							}
							depth--
							add(ruleComment, position144)
						}
						break
					default:
						if !_rules[ruleSpace]() {
							goto l141
						}
					l148:
						{
							position149, tokenIndex149, depth149 := position, tokenIndex, depth
							if !_rules[ruleSpace]() {
								goto l149
							}
							goto l148
						l149:
							position, tokenIndex, depth = position149, tokenIndex149, depth149
						}
						break
					}
				}

				depth--
				add(ruleSpaceComment, position142)
			}
			return true
		l141:
			position, tokenIndex, depth = position141, tokenIndex141, depth141
			return false
		},
		/* 10 Comment <- <('#' (!EndOfLine .)* EndOfLine)> */
		nil,
		/* 11 Space <- <(' ' / '\t')> */
		func() bool {
			position151, tokenIndex151, depth151 := position, tokenIndex, depth
			{
				position152 := position
				depth++
				{
					position153, tokenIndex153, depth153 := position, tokenIndex, depth
					if buffer[position] != rune(' ') {
						goto l154
					}
					position++
					goto l153
				l154:
					position, tokenIndex, depth = position153, tokenIndex153, depth153
					if buffer[position] != rune('\t') {
						goto l151
					}
					position++
				}
			l153:
				depth--
				add(ruleSpace, position152)
			}
			return true
		l151:
			position, tokenIndex, depth = position151, tokenIndex151, depth151
			return false
		},
		/* 12 EndOfLine <- <(('\r' '\n') / '\n' / '\r')> */
		func() bool {
			position155, tokenIndex155, depth155 := position, tokenIndex, depth
			{
				position156 := position
				depth++
				{
					position157, tokenIndex157, depth157 := position, tokenIndex, depth
					if buffer[position] != rune('\r') {
						goto l158
					}
					position++
					if buffer[position] != rune('\n') {
						goto l158
					}
					position++
					goto l157
				l158:
					position, tokenIndex, depth = position157, tokenIndex157, depth157
					if buffer[position] != rune('\n') {
						goto l159
					}
					position++
					goto l157
				l159:
					position, tokenIndex, depth = position157, tokenIndex157, depth157
					if buffer[position] != rune('\r') {
						goto l155
					}
					position++
				}
			l157:
				depth--
				add(ruleEndOfLine, position156)
			}
			return true
		l155:
			position, tokenIndex, depth = position155, tokenIndex155, depth155
			return false
		},
		nil,
		/* 15 Action0 <- <{ p.addSection(text) }> */
		nil,
		/* 16 Action1 <- <{ p.setID(text) }> */
		nil,
		/* 17 Action2 <- <{ p.setKey(text) }> */
		nil,
		/* 18 Action3 <- <{ p.addValue(text) }> */
		nil,
		/* 19 Action4 <- <{ p.setKey(text) }> */
		nil,
		/* 20 Action5 <- <{ p.addValue(text) }> */
		nil,
	}
	p.rules = _rules
}
