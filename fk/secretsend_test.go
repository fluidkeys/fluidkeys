package fk

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/fluidkeys/crypto/openpgp"
	"github.com/fluidkeys/crypto/openpgp/armor"
	"github.com/fluidkeys/fluidkeys/assert"
	"github.com/fluidkeys/fluidkeys/exampledata"
	"github.com/fluidkeys/fluidkeys/pgpkey"
	"github.com/minimaxir/big-list-of-naughty-strings/naughtystrings"
)

func TestEncryptSecret(t *testing.T) {
	secret := "Secret message!"

	pgpKey, err := pgpkey.LoadFromArmoredEncryptedPrivateKey(exampledata.ExamplePrivateKey4, "test4")
	if err != nil {
		t.Fatalf("error loading private key: %s", err)
	}

	t.Run("containing a disallowed rune", func(t *testing.T) {
		secretWithDisallowedRune := "\x1b[40mBlocked secret message!\x1b[0m"

		_, err := encryptSecret(secretWithDisallowedRune, "", pgpKey)
		assert.ErrorIsNotNil(t, err)
	})

	t.Run("with an empty filename", func(t *testing.T) {
		armoredEncryptedSecret, err := encryptSecret(secret, "", pgpKey)
		assert.ErrorIsNil(t, err)

		messageDetails := decryptMessageDetails(armoredEncryptedSecret, pgpKey, t)
		assertMessageBodyMatchesSecretContent(messageDetails.UnverifiedBody, secret, t)
		assert.Equal(t, "_CONSOLE", messageDetails.LiteralData.FileName)
		if messageDetails.LiteralData.ForEyesOnly() != true {
			t.Fatalf("expected secret to be For Eyes Only, but isn't")
		}
	})

	t.Run("with a filename", func(t *testing.T) {
		armoredEncryptedSecret, err := encryptSecret(secret, "secret.txt", pgpKey)
		assert.ErrorIsNil(t, err)

		messageDetails := decryptMessageDetails(armoredEncryptedSecret, pgpKey, t)
		assertMessageBodyMatchesSecretContent(messageDetails.UnverifiedBody, secret, t)
		assert.Equal(t, "secret.txt", messageDetails.LiteralData.FileName)
		if messageDetails.LiteralData.ForEyesOnly() == true {
			t.Fatalf("expected secret not to be For Eyes Only, but is")
		}
	})

}

func decryptMessageDetails(armoredEncryptedSecret string, pgpKey *pgpkey.PgpKey, t *testing.T) *openpgp.MessageDetails {
	t.Helper()

	buf := strings.NewReader(armoredEncryptedSecret)

	block, err := armor.Decode(buf)
	if err != nil {
		t.Fatalf("error decoding armor: %s", err)
	}

	var keyRing openpgp.EntityList = []*openpgp.Entity{&pgpKey.Entity}

	messageDetails, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	if err != nil {
		t.Fatalf("error rereading message: %s", err)
	}

	return messageDetails
}

func assertMessageBodyMatchesSecretContent(unverifiedBody io.Reader, secret string, t *testing.T) {
	t.Helper()

	messageBuf := bytes.NewBuffer(nil)
	_, err := io.Copy(messageBuf, unverifiedBody)
	if err != nil {
		t.Fatalf("error rereading message: %s", err)
	}
	if !bytes.Equal([]byte(secret), messageBuf.Bytes()) {
		t.Fatalf("recovered message incorrect got '%s', want '%s'", messageBuf.Bytes(), secret)
	}
}

func TestContainsDisallowedRunes(t *testing.T) {

	t.Run("latin alphabet characters should be allowed", func(t *testing.T) {
		latinAlphabet := "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz"
		assert.Equal(t, false, containsDisallowedRune(latinAlphabet))

	})

	t.Run("valid printable characters should be allowed", func(t *testing.T) {
		printableCharacters := "☠☮☯♠Ω♤♣♧♥♡♦♢♔♕♚♛⚜★☆✮✯☄☾☽☼☀☁☂☃☻☺☹۞۩ εїзƸ̵̡Ӝ̵̨̄ƷξЖЗεжз☎☏¢☚☛"
		assert.Equal(t, false, containsDisallowedRune(printableCharacters))
	})

	t.Run("emojis should be allowed", func(t *testing.T) {
		sampleEmojis := "😀😁😂🤣😃😄😅😆😉😊😋😎😍😘😗😙😚🙂"
		assert.Equal(t, false, containsDisallowedRune(sampleEmojis))
	})

	t.Run("line breaks should be allowed", func(t *testing.T) {
		lineBreaks := "line 1\rline 2\n"
		assert.Equal(t, false, containsDisallowedRune(lineBreaks))
	})

	t.Run("terminal control codes should not be allowed", func(t *testing.T) {
		invalidColorCharacters := map[string]string{
			"reset":      "\x1b[0m",
			"bright":     "\x1b[1m",
			"dim":        "\x1b[2m",
			"underscore": "\x1b[4m",
			"blink":      "\x1b[5m",
			"reverse":    "\x1b[7m",
			"hidden":     "\x1b[8m",

			"fgBlack":   "\x1b[30m",
			"fgRed":     "\x1b[31m",
			"fgGreen":   "\x1b[32m",
			"fgYellow":  "\x1b[33m",
			"fgBlue":    "\x1b[34m",
			"fgMagenta": "\x1b[35m",
			"fgCyan":    "\x1b[36m",
			"fgWhite":   "\x1b[37m",

			"bgBlack":     "\x1b[40m",
			"bgRed":       "\x1b[41m",
			"bgGreen":     "\x1b[42m",
			"bgYellow":    "\x1b[43m",
			"bgBlue":      "\x1b[44m",
			"bgMagenta":   "\x1b[45m",
			"bgCyan":      "\x1b[46m",
			"bgWhite":     "\x1b[47m",
			"bgLightBlue": "\x1b[104m",
		}

		for name, code := range invalidColorCharacters {
			if containsDisallowedRune(code) != true {
				t.Fatalf("expected '%v' (%v) to be disallowed but it wasn't", code, name)
			}
		}
	})

	t.Run("certain ANSI codes should not be allowed", func(t *testing.T) {

		invalidANSICodes := map[string]string{
			"NUL":    "\000",     // Null
			"SOH":    "\001",     // Start of Heading
			"STX":    "\002",     // Start of Text
			"ETX":    "\003",     // End of Text
			"EOT":    "\004",     // End of Transmission
			"ENQ":    "\005",     // Enquiry
			"ACK":    "\006",     // Acknowledge
			"BEL":    "\007",     // Bell
			"BS":     "\010",     // Backspace
			"HT":     "\011",     // Character Tabulation
			"VT":     "\013",     // Line Tabulation
			"FF":     "\014",     // Form Feed
			"SO":     "\016",     // Shift-Out
			"SI":     "\017",     // Shift-In
			"DLE":    "\020",     // Data Link Escape
			"DC1":    "\021",     // Device Control One
			"DC2":    "\022",     // Device Control Two
			"DC3":    "\023",     // Device Control Three
			"DC4":    "\024",     // Device Control Four
			"NAK":    "\025",     // Negative Acknowledge
			"SYN":    "\026",     // Synchronous Idle
			"ETB":    "\027",     // End of Transmission Block
			"CAN":    "\030",     // Cancel
			"EM":     "\031",     // End of Medium
			"SUB":    "\032",     // Substitute
			"ESC":    "\033",     // Escape
			"IS4":    "\034",     // Information Separator Four (FS - File Separator)
			"IS3":    "\035",     // Information Separator Three (GS - Group Separator)
			"IS2":    "\036",     // Information Separator Two (RS - Record Separator)
			"IS1":    "\037",     // Information Separator One (US - Unit Separator)
			"APC":    "\033_",    // Application Program Command
			"BPH":    "\033B",    // Break Permitted Here
			"CBT":    "\033[Z",   // Cursor Backward Tabulation
			"CCH":    "\033T",    // Cancel Character
			"CHA":    "\033[G",   // Cursor Character Absolute
			"CHT":    "\033[I",   // Cursor Forward Tabulation
			"CMD":    "\033d",    // Coding Method Delimiter
			"CNL":    "\033[E",   // Cursor Next Line
			"CPL":    "\033[F",   // Cursor Preceding Line
			"CPR":    "\033[R",   // Active Position Report
			"CSI":    "\033[",    // Control Sequence Introducer
			"CTC":    "\033[W",   // Cursor Tabulation Control
			"CUB":    "\033[D",   // Cursor Left
			"CUD":    "\033[B",   // Cursor Down
			"CUF":    "\033[C",   // Cursor Right
			"CUP":    "\033[H",   // Cursor Position
			"CUU":    "\033[A",   // Cursor Up
			"CVT":    "\033[Y",   // Cursor Line Tabulation
			"DA":     "\033[c",   // Device Attributes
			"DAQ":    "\033[o",   // Define Area Qualification
			"DCH":    "\033[P",   // Delete Character
			"DCS":    "\033P",    // Device Control String
			"DL":     "\033[M",   // Delete Line
			"DMI":    "\033`",    // Disable Manual Input
			"DSR":    "\033[n",   // Device Status Report
			"DTA":    "\033[ T",  // Dimension Text Area
			"EA":     "\033[O",   // Erase in Area
			"ECH":    "\033[X",   // Erase Character
			"ED":     "\033[J",   // Erase in Page
			"EF":     "\033[N",   // Erase in Field
			"EL":     "\033[K",   // Erase in Line
			"EMI":    "\033b",    // Enable Manual Input
			"EPA":    "\033W",    // End of Guarded Area
			"ESA":    "\033G",    // End of Selected Area
			"FNK":    "\033[ W",  // Function Key
			"FNT":    "\033[ D",  // Font Selection
			"GCC":    "\033[ _",  // Graphic Character Combination
			"GSM":    "\033[ B",  // Graphic Size Modification
			"GSS":    "\033[ C",  // Graphic Size Selection
			"HPA":    "\033[`",   // Character Position Absolute
			"HPB":    "\033[j",   // Character Position Backward
			"HPR":    "\033[a",   // Character Position Forward
			"HTJ":    "\033I",    // Character Tabulation With Justification
			"HTS":    "\033H",    // Character Tabulation Set
			"HVP":    "\033[f",   // Character and Line Position
			"ICH":    "\033[@",   // Insert Character
			"IDCS":   "\033[ O",  // Identify Device Control String
			"IGS":    "\033[ M",  // Identify Graphic Subrepertoire
			"IL":     "\033[L",   // Insert Line
			"INT":    "\033a",    // Interrupt
			"JFY":    "\033[ F",  // Justify
			"LS1R":   "\033~",    // Locking-Shift One Right
			"LS2":    "\033n",    // Locking-Shift Two
			"LS2R":   "\033}",    // Locking-Shift Two Right
			"LS3":    "\033o",    // Locking-Shift Three
			"LS3R":   "\033|",    // Locking-Shift Three Right
			"MC":     "\033[i",   // Media Copy
			"MW":     "\033U",    // Message Waiting
			"NBH":    "\033C",    // No Break Here
			"NEL":    "\033E",    // Next Line
			"NP":     "\033[U",   // Next Page
			"OSC":    "\033]",    // Operating System Command
			"PEC":    "\033[ Z",  // Presentation Expand or Contract
			"PFS":    "\033[ J",  // Page Format Selection
			"PLD":    "\033K",    // Partial Line Forward
			"PLU":    "\033L",    // Partial Line Backward
			"PM":     "\033^",    // Privacy Message
			"PP":     "\033[V",   // Preceding Page
			"PPA":    "\033[ P",  // Page Position Absolute
			"PPB":    "\033[ R",  // Page Position Backward
			"PPR":    "\033[ Q",  // Page Position Forward
			"PTX":    "\033[\\",  // Parallel Texts
			"PU1":    "\033Q",    // Private Use One
			"PU2":    "\033R",    // Private Use Two
			"QUAD":   "\033[ H",  // Quad
			"REP":    "\033[b",   // Repeat
			"RI":     "\033M",    // Reverse Line Feed
			"RIS":    "\033c",    // Reset to Initial State
			"RM":     "\033[l",   // Reset Mode
			"SACS":   "\033[ \\", // Set Additional Character Separation
			"SAPV":   "\033[ ]",  // Select Alternative Presentation Variants
			"SCI":    "\033Z",    // Single Character Introducer
			"SCO":    "\033[ e",  // Select Character Orientation
			"SCP":    "\033[ k",  // Select Character Path
			"SCS":    "\033[ g",  // Set Character Spacing
			"SD":     "\033[T",   // Scroll Down
			"SDS":    "\033[]",   // Start Directed String
			"SEE":    "\033[Q",   // Select Editing Extent
			"SEF":    "\033[ Y",  // Sheet Eject and Feed
			"SGR":    "\033[m",   // Select Graphic Rendition
			"SHS":    "\033[ K",  // Select Character Spacing
			"SIMD":   "\033[^",   // Select Implicit Movement Direction
			"SL":     "\033[ @",  // Scroll Left
			"SLH":    "\033[ U",  // Set Line Home
			"SLL":    "\033[ V",  // Set Line Limit
			"SLS":    "\033[ h",  // Set Line Spacing
			"SM":     "\033[h",   // Set Mode
			"SOS":    "\033X",    // Start of String
			"SPA":    "\033V",    // Start of Guarded Area
			"SPD":    "\033[ S",  // Select Presentation Directions
			"SPH":    "\033[ i",  // Set Page Home
			"SPI":    "\033[ G",  // Spacing Increment
			"SPL":    "\033[ j",  // Set Page Limit
			"SPQR":   "\033[ X",  // Select Print Quality and Rapidity
			"SR":     "\033[ A",  // Scroll Right
			"SRCS":   "\033[ f",  // Set Reduced Character Separation
			"SRS":    "\033[[",   // Start Reversed String
			"SSA":    "\033F",    // Start of Selected Area
			"SSU":    "\033[ I",  // Select Size Unit
			"SSW":    "\033[ [",  // Set Space Width
			"SS2":    "\033N",    // Single-Shift Two
			"SS3":    "\033O",    // Single-Shift Three
			"ST":     "\033\\",   // String Terminator
			"STAB":   "\033[ ^",  // Selective Tabulation
			"STS":    "\033S",    // Set Transmit State
			"SU":     "\033[S",   // Scroll Up
			"SVS":    "\033[ L",  // Select Line Spacing
			"TAC":    "\033[ b",  // Tabulation Aligned Centred
			"TALE":   "\033[ a",  // Tabulation Aligned Leading Edge
			"TATE":   "\033[ `",  // Tabulation Aligned Trailing Edge
			"TBC":    "\033[g",   // Tabulation Clear
			"TCC":    "\033[ c",  // Tabulation Centred on Character
			"TSR":    "\033[ d",  // Tabulation Stop Remove
			"TSS":    "\033[ E",  // Thin Space Specification
			"VPA":    "\033[d",   // Line Position Absolute
			"VPB":    "\033[k",   // Line Position Backward
			"VPR":    "\033[e",   // Line Position Forward
			"VTS":    "\033J",    // Line Tabulation Set
			"C0":     "\033!@",   // Control Set 0 Announcer
			"C1":     "\033&@",   // Control Set 1 Announcer
			"C1ALT1": "\033 F",   // Control Set 1 Announcer Alternate 1
			"C1ALT2": "\033\"F",  // Control Set 1 Announcer Alternate 2
		}

		for name, code := range invalidANSICodes {
			if containsDisallowedRune(code) != true {
				t.Fatalf("expected '%v' (%v) to be a disallowed but it wasn't", code, name)
			}
		}
	})

	t.Run("'naughty strings' should all run without crashing", func(t *testing.T) {
		for _, naughtyString := range naughtystrings.Unencoded() {
			containsDisallowedRune(naughtyString)
		}
	})
}
