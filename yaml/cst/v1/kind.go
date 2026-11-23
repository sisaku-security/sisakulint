package cst

// TokenKind is the kind of a token. Tokens tile the input: whitespace,
// line breaks and comments are tokens like any other.
type TokenKind uint8

const (
	TokError TokenKind = iota
	TokBOM
	TokSpace   // spaces and tabs within a line
	TokNewline // one b-break: \r\n, \r or \n
	TokComment // from '#' to the end of the line, excluding the break
	TokSeqEntry
	TokMapKey
	TokMapValue
	TokFlowEntry
	TokFlowSeqStart
	TokFlowSeqEnd
	TokFlowMapStart
	TokFlowMapEnd
	TokBlockHeader // '|' or '>' with its indentation and chomping indicators
	TokDocStart
	TokDocEnd
	TokAnchor
	TokAlias
	TokTag
	TokDirective // '%' and the directive name
	TokDirectiveParam
	TokPlain        // one line of a plain scalar
	TokSingleQuoted // one line of a single-quoted scalar, quotes included
	TokDoubleQuoted // one line of a double-quoted scalar, quotes included
	TokBlockContent // one line of block scalar content; indentation is a TokSpace
)

var tokenKindNames = [...]string{
	TokError:          "Error",
	TokBOM:            "BOM",
	TokSpace:          "Space",
	TokNewline:        "Newline",
	TokComment:        "Comment",
	TokSeqEntry:       "SeqEntry",
	TokMapKey:         "MapKey",
	TokMapValue:       "MapValue",
	TokFlowEntry:      "FlowEntry",
	TokFlowSeqStart:   "FlowSeqStart",
	TokFlowSeqEnd:     "FlowSeqEnd",
	TokFlowMapStart:   "FlowMapStart",
	TokFlowMapEnd:     "FlowMapEnd",
	TokBlockHeader:    "BlockHeader",
	TokDocStart:       "DocStart",
	TokDocEnd:         "DocEnd",
	TokAnchor:         "Anchor",
	TokAlias:          "Alias",
	TokTag:            "Tag",
	TokDirective:      "Directive",
	TokDirectiveParam: "DirectiveParam",
	TokPlain:          "Plain",
	TokSingleQuoted:   "SingleQuoted",
	TokDoubleQuoted:   "DoubleQuoted",
	TokBlockContent:   "BlockContent",
}

func (k TokenKind) String() string {
	if int(k) < len(tokenKindNames) {
		return tokenKindNames[k]
	}
	return "TokenKind(?)"
}

// NodeKind is the kind of a node.
type NodeKind uint8

const (
	NodeError NodeKind = iota
	NodeStream
	NodeDocument
	NodeDirective
	NodeBlockMapping
	NodeBlockMappingEntry
	NodeBlockSequence
	NodeBlockSequenceEntry
	NodeFlowMapping
	NodeFlowSequence
	NodeFlowPair
	NodeProperties
	NodeAlias
	NodeScalar
)

var nodeKindNames = [...]string{
	NodeError:              "Error",
	NodeStream:             "Stream",
	NodeDocument:           "Document",
	NodeDirective:          "Directive",
	NodeBlockMapping:       "BlockMapping",
	NodeBlockMappingEntry:  "BlockMappingEntry",
	NodeBlockSequence:      "BlockSequence",
	NodeBlockSequenceEntry: "BlockSequenceEntry",
	NodeFlowMapping:        "FlowMapping",
	NodeFlowSequence:       "FlowSequence",
	NodeFlowPair:           "FlowPair",
	NodeProperties:         "Properties",
	NodeAlias:              "Alias",
	NodeScalar:             "Scalar",
}

func (k NodeKind) String() string {
	if int(k) < len(nodeKindNames) {
		return nodeKindNames[k]
	}
	return "NodeKind(?)"
}
