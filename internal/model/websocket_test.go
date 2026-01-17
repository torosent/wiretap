package model

import "testing"

func TestWebSocketOpcode_String(t *testing.T) {
	tests := []struct {
		opcode WebSocketOpcode
		expect string
	}{
		{WebSocketOpcodeContinuation, "Continuation"},
		{WebSocketOpcodeText, "Text"},
		{WebSocketOpcodeBinary, "Binary"},
		{WebSocketOpcodeClose, "Close"},
		{WebSocketOpcodePing, "Ping"},
		{WebSocketOpcodePong, "Pong"},
		{WebSocketOpcode(0x3), "Unknown(3)"},
		{WebSocketOpcode(0xB), "Unknown(11)"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			got := tt.opcode.String()
			if got != tt.expect {
				t.Errorf("String() = %s, want %s", got, tt.expect)
			}
		})
	}
}

func TestWebSocketOpcode_IsControl(t *testing.T) {
	tests := []struct {
		opcode WebSocketOpcode
		isCtrl bool
	}{
		{WebSocketOpcodeContinuation, false},
		{WebSocketOpcodeText, false},
		{WebSocketOpcodeBinary, false},
		{WebSocketOpcodeClose, true},
		{WebSocketOpcodePing, true},
		{WebSocketOpcodePong, true},
		{WebSocketOpcode(0x7), false},
		{WebSocketOpcode(0x8), true},
	}

	for _, tt := range tests {
		t.Run(tt.opcode.String(), func(t *testing.T) {
			got := tt.opcode.IsControl()
			if got != tt.isCtrl {
				t.Errorf("IsControl() = %v, want %v", got, tt.isCtrl)
			}
		})
	}
}

func TestWebSocketHandshake_SecWebSocketKey(t *testing.T) {
	tests := []struct {
		name      string
		handshake WebSocketHandshake
		expect    string
	}{
		{
			name: "from headers",
			handshake: WebSocketHandshake{
				Headers: map[string]string{
					"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
				},
			},
			expect: "dGhlIHNhbXBsZSBub25jZQ==",
		},
		{
			name: "from Key field",
			handshake: WebSocketHandshake{
				Key: "fallback-key",
			},
			expect: "fallback-key",
		},
		{
			name: "headers take precedence",
			handshake: WebSocketHandshake{
				Headers: map[string]string{
					"Sec-WebSocket-Key": "header-key",
				},
				Key: "field-key",
			},
			expect: "header-key",
		},
		{
			name:      "empty",
			handshake: WebSocketHandshake{},
			expect:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.handshake.SecWebSocketKey()
			if got != tt.expect {
				t.Errorf("SecWebSocketKey() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWebSocketHandshake_SecWebSocketProtocol(t *testing.T) {
	tests := []struct {
		name      string
		handshake WebSocketHandshake
		expect    string
	}{
		{
			name: "from headers",
			handshake: WebSocketHandshake{
				Headers: map[string]string{
					"Sec-WebSocket-Protocol": "graphql-ws",
				},
			},
			expect: "graphql-ws",
		},
		{
			name: "from Protocol field",
			handshake: WebSocketHandshake{
				Protocol: "chat",
			},
			expect: "chat",
		},
		{
			name: "headers take precedence",
			handshake: WebSocketHandshake{
				Headers: map[string]string{
					"Sec-WebSocket-Protocol": "header-proto",
				},
				Protocol: "field-proto",
			},
			expect: "header-proto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.handshake.SecWebSocketProtocol()
			if got != tt.expect {
				t.Errorf("SecWebSocketProtocol() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWebSocketFrame_OpcodeType(t *testing.T) {
	frame := &WebSocketFrame{Opcode: 0x1}
	if frame.OpcodeType() != WebSocketOpcodeText {
		t.Error("OpcodeType should return Text")
	}
}

func TestWebSocketFrame_FrameTypeChecks(t *testing.T) {
	tests := []struct {
		opcode   uint8
		isText   bool
		isBinary bool
		isClose  bool
		isPing   bool
		isPong   bool
		isCtrl   bool
	}{
		{0x0, false, false, false, false, false, false}, // continuation
		{0x1, true, false, false, false, false, false},  // text
		{0x2, false, true, false, false, false, false},  // binary
		{0x8, false, false, true, false, false, true},   // close
		{0x9, false, false, false, true, false, true},   // ping
		{0xA, false, false, false, false, true, true},   // pong
	}

	for _, tt := range tests {
		frame := &WebSocketFrame{Opcode: tt.opcode}

		if frame.IsText() != tt.isText {
			t.Errorf("Opcode %x: IsText() = %v, want %v", tt.opcode, frame.IsText(), tt.isText)
		}
		if frame.IsBinary() != tt.isBinary {
			t.Errorf("Opcode %x: IsBinary() = %v, want %v", tt.opcode, frame.IsBinary(), tt.isBinary)
		}
		if frame.IsClose() != tt.isClose {
			t.Errorf("Opcode %x: IsClose() = %v, want %v", tt.opcode, frame.IsClose(), tt.isClose)
		}
		if frame.IsPing() != tt.isPing {
			t.Errorf("Opcode %x: IsPing() = %v, want %v", tt.opcode, frame.IsPing(), tt.isPing)
		}
		if frame.IsPong() != tt.isPong {
			t.Errorf("Opcode %x: IsPong() = %v, want %v", tt.opcode, frame.IsPong(), tt.isPong)
		}
		if frame.IsControl() != tt.isCtrl {
			t.Errorf("Opcode %x: IsControl() = %v, want %v", tt.opcode, frame.IsControl(), tt.isCtrl)
		}
	}
}

func TestWebSocketFrame_Summary(t *testing.T) {
	tests := []struct {
		name   string
		frame  WebSocketFrame
		expect string
	}{
		{
			name: "text frame short",
			frame: WebSocketFrame{
				Opcode:        uint8(WebSocketOpcodeText),
				PayloadLength: 5,
				Payload:       []byte("hello"),
			},
			expect: `WebSocket Text: "hello"`,
		},
		{
			name: "text frame long",
			frame: WebSocketFrame{
				Opcode:        uint8(WebSocketOpcodeText),
				PayloadLength: 100,
				Payload:       []byte("this is a very long message that exceeds fifty characters in length and should be truncated"),
			},
			expect: `WebSocket Text: "this is a very long message that exceeds fifty cha..."`,
		},
		{
			name: "binary frame",
			frame: WebSocketFrame{
				Opcode:        uint8(WebSocketOpcodeBinary),
				PayloadLength: 256,
			},
			expect: "WebSocket Binary (256 bytes)",
		},
		{
			name: "ping frame no payload",
			frame: WebSocketFrame{
				Opcode: uint8(WebSocketOpcodePing),
			},
			expect: "WebSocket Ping",
		},
		{
			name: "close frame",
			frame: WebSocketFrame{
				Opcode:        uint8(WebSocketOpcodeClose),
				PayloadLength: 2,
			},
			expect: "WebSocket Close (2 bytes)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.frame.Summary()
			if got != tt.expect {
				t.Errorf("Summary() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWebSocketFrame_CloseCode(t *testing.T) {
	tests := []struct {
		name   string
		frame  WebSocketFrame
		expect uint16
	}{
		{
			name: "normal closure",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeClose),
				Payload: []byte{0x03, 0xE8}, // 1000
			},
			expect: 1000,
		},
		{
			name: "going away",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeClose),
				Payload: []byte{0x03, 0xE9}, // 1001
			},
			expect: 1001,
		},
		{
			name: "not close frame",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeText),
				Payload: []byte{0x03, 0xE8},
			},
			expect: 0,
		},
		{
			name: "payload too short",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeClose),
				Payload: []byte{0x03},
			},
			expect: 0,
		},
		{
			name: "no payload",
			frame: WebSocketFrame{
				Opcode: uint8(WebSocketOpcodeClose),
			},
			expect: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.frame.CloseCode()
			if got != tt.expect {
				t.Errorf("CloseCode() = %d, want %d", got, tt.expect)
			}
		})
	}
}

func TestWebSocketFrame_CloseReason(t *testing.T) {
	tests := []struct {
		name   string
		frame  WebSocketFrame
		expect string
	}{
		{
			name: "with reason",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeClose),
				Payload: []byte{0x03, 0xE8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'},
			},
			expect: "goodbye",
		},
		{
			name: "code only",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeClose),
				Payload: []byte{0x03, 0xE8},
			},
			expect: "",
		},
		{
			name: "not close frame",
			frame: WebSocketFrame{
				Opcode:  uint8(WebSocketOpcodeText),
				Payload: []byte("hello"),
			},
			expect: "",
		},
		{
			name: "no payload",
			frame: WebSocketFrame{
				Opcode: uint8(WebSocketOpcodeClose),
			},
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.frame.CloseReason()
			if got != tt.expect {
				t.Errorf("CloseReason() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestWebSocketFrame_TextPayload(t *testing.T) {
	frame := &WebSocketFrame{
		Payload: []byte("hello world"),
	}
	if frame.TextPayload() != "hello world" {
		t.Errorf("TextPayload() = %q, want %q", frame.TextPayload(), "hello world")
	}

	emptyFrame := &WebSocketFrame{}
	if emptyFrame.TextPayload() != "" {
		t.Error("TextPayload() should be empty for frame with no payload")
	}
}
