// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestDiscordGatewayCarrierIndependentFieldDetection(t *testing.T) {
	s := MustNew(credentialAudienceTestConfig())
	t.Cleanup(s.Close)
	credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	extra := fmt.Sprintf(`[%q,%q]`, "hf_"+strings.Repeat("a", 34), base64.StdEncoding.EncodeToString([]byte(credential)))
	frame := fmt.Sprintf(`{"op":2,"d":{"token":%q,"extra":%s}}`, credential, extra)
	surface, _, invalid := s.WebSocketCredentialAudienceSurface(t.Context(), []byte(frame), "wss://gateway.discord.gg/")
	if surface != "websocket_frame" || invalid {
		t.Fatalf("another pattern masked a credential copy: surface=%q invalid=%t", surface, invalid)
	}
}
