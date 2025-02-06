package apiv1

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto" // For secp256k1 (ES256K)
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

const pid_sd_vc_jwt_with_selective_disclosures_and_holder_binding = "eyJ0eXAiOiJKV1QiLCJ2Y3RtIjpbImV5SjJZM1FpT2lKMWNtNDZZM0psWkdWdWRHbGhiRHAyYVdRaUxDSnVZVzFsSWpvaVVFbEVJaXdpWkdWelkzSnBjSFJwYjI0aU9pSlVhR2x6SUdseklHRWdVRWxFSUdSdlkzVnRaVzUwSUdsemMzVmxaQ0JpZVNCMGFHVWdkMlZzYkNCcmJtOTNiaUJXU1VRZ1NYTnpkV1Z5SWl3aVpHbHpjR3hoZVNJNlczc2libUZ0WlNJNklsQkpSQ0lzSW5KbGJtUmxjbWx1WnlJNmV5SnphVzF3YkdVaU9uc2liRzluYnlJNmV5SjFjbWtpT2lKb2RIUndjem92TDNsdmRYSmxkV1JwTG1Sak5HVjFMbVYxTDJsdFlXZGxjeTkyYVdSRFlYSmtMbkJ1WnlJc0luVnlhU05wYm5SbFozSnBkSGtpT2lKemFHRXlOVFl0WVdOa1lUTTBNRFJqTW1ObU5EWmtZVEU1TW1ObU1qUTFZMk5qTm1JNU1XVmtZMlU0T0RZNU1USXlabUUxWVRZMk16WXlPRFJtTVdFMk1HWm1ZMlE0TmlJc0ltRnNkRjkwWlhoMElqb2lWa2xFSUVOaGNtUWlmU3dpWW1GamEyZHliM1Z1WkY5amIyeHZjaUk2SWlNeE1qRXdOMk1pTENKMFpYaDBYMk52Ykc5eUlqb2lJMFpHUmtaR1JpSjlMQ0p6ZG1kZmRHVnRjR3hoZEdWeklqcGJleUoxY21raU9pSm9kSFJ3Y3pvdkwzbHZkWEpsZFdScExtUmpOR1YxTG1WMUwybHRZV2RsY3k5cFpGUmxiWEJzWVhSbExuTjJaeUo5WFgxOVhTd2lZMnhoYVcxeklqcGJleUp3WVhSb0lqcGJJbWRwZG1WdVgyNWhiV1VpWFN3aVpHbHpjR3hoZVNJNmV5SmxiaTFWVXlJNmV5SnNZV0psYkNJNklrZHBkbVZ1SUU1aGJXVWlMQ0prWlhOamNtbHdkR2x2YmlJNklsUm9aU0JuYVhabGJpQnVZVzFsSUc5bUlIUm9aU0JXU1VRZ2FHOXNaR1Z5SW4xOUxDSjJaWEpwWm1sallYUnBiMjRpT2lKMlpYSnBabWxsWkNJc0luTmtJam9pWVd4c2IzZGxaQ0lzSW5OMloxOXBaQ0k2SW1kcGRtVnVYMjVoYldVaWZTeDdJbkJoZEdnaU9sc2labUZ0YVd4NVgyNWhiV1VpWFN3aVpHbHpjR3hoZVNJNmV5SmxiaTFWVXlJNmV5SnNZV0psYkNJNklrWmhiV2xzZVNCT1lXMWxJaXdpWkdWelkzSnBjSFJwYjI0aU9pSlVhR1VnWm1GdGFXeDVJRzVoYldVZ2IyWWdkR2hsSUZaSlJDQm9iMnhrWlhJaWZYMHNJblpsY21sbWFXTmhkR2x2YmlJNkluWmxjbWxtYVdWa0lpd2ljMlFpT2lKaGJHeHZkMlZrSWl3aWMzWm5YMmxrSWpvaVptRnRhV3g1WDI1aGJXVWlmU3g3SW5CaGRHZ2lPbHNpWW1seWRHaGZaR0YwWlNKZExDSmthWE53YkdGNUlqcDdJbVZ1TFZWVElqcDdJbXhoWW1Wc0lqb2lRbWx5ZEdnZ1JHRjBaU0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hsSUdKcGNuUm9JR1JoZEdVZ2IyWWdkR2hsSUZaSlJDQm9iMnhrWlhJaWZYMHNJblpsY21sbWFXTmhkR2x2YmlJNkluWmxjbWxtYVdWa0lpd2ljMlFpT2lKaGJHeHZkMlZrSWl3aWMzWm5YMmxrSWpvaVltbHlkR2hmWkdGMFpTSjlMSHNpY0dGMGFDSTZXeUpwYzNOMWFXNW5YMkYxZEdodmNtbDBlU0pkTENKa2FYTndiR0Y1SWpwN0ltVnVMVlZUSWpwN0lteGhZbVZzSWpvaVNYTnpkV2x1WnlCQmRYUm9iM0pwZEhraUxDSmtaWE5qY21sd2RHbHZiaUk2SWxSb1pTQmpiM1Z1ZEhKNUlHTnZaR1VnYjJZZ2RHaGxJR0YxZEdodmNtbDBlU0IwYUdGMElHbHpjM1ZsWkNCMGFHbHpJR055WldSbGJuUnBZV3dpZlgwc0luWmxjbWxtYVdOaGRHbHZiaUk2SW1GMWRHaHZjbWwwWVhScGRtVWlMQ0p6WkNJNkltRnNiRzkzWldRaUxDSnpkbWRmYVdRaU9pSnBjM04xYVc1blgyRjFkR2h2Y21sMGVTSjlMSHNpY0dGMGFDSTZXeUpwYzNOMVlXNWpaVjlrWVhSbElsMHNJbVJwYzNCc1lYa2lPbnNpWlc0dFZWTWlPbnNpYkdGaVpXd2lPaUpKYzNOMVlXNWpaU0JFWVhSbElpd2laR1Z6WTNKcGNIUnBiMjRpT2lKVWFHVWdaR0YwWlNCaGJtUWdkR2x0WlNCcGMzTjFaV1FnZEdocGN5QmpjbVZrWlc1MGFXRnNJbjE5TENKMlpYSnBabWxqWVhScGIyNGlPaUpoZFhSb2IzSnBkR0YwYVhabElpd2ljMlFpT2lKaGJHeHZkMlZrSWl3aWMzWm5YMmxrSWpvaWFYTnpkV0Z1WTJWZlpHRjBaU0o5TEhzaWNHRjBhQ0k2V3lKbGVIQnBjbmxmWkdGMFpTSmRMQ0prYVhOd2JHRjVJanA3SW1WdUxWVlRJanA3SW14aFltVnNJam9pUlhod2FYSjVJRVJoZEdVaUxDSmtaWE5qY21sd2RHbHZiaUk2SWxSb1pTQmtZWFJsSUdGdVpDQjBhVzFsSUdWNGNHbHlaV1FnZEdocGN5QmpjbVZrWlc1MGFXRnNJbjE5TENKMlpYSnBabWxqWVhScGIyNGlPaUpoZFhSb2IzSnBkR0YwYVhabElpd2ljMlFpT2lKaGJHeHZkMlZrSWl3aWMzWm5YMmxrSWpvaVpYaHdhWEo1WDJSaGRHVWlmVjBzSW5OamFHVnRZU0k2ZXlJa2MyTm9aVzFoSWpvaWFIUjBjRG92TDJwemIyNHRjMk5vWlcxaExtOXlaeTlrY21GbWRDMHdOeTl6WTJobGJXRWpJaXdpZEhsd1pTSTZJbTlpYW1WamRDSXNJbkJ5YjNCbGNuUnBaWE1pT25zaVoybDJaVzVmYm1GdFpTSTZleUowZVhCbElqb2ljM1J5YVc1bkluMHNJbVpoYldsc2VWOXVZVzFsSWpwN0luUjVjR1VpT2lKemRISnBibWNpZlN3aVltbHlkR2hmWkdGMFpTSTZleUowZVhCbElqb2ljM1J5YVc1bkluMHNJbWx6YzNWcGJtZGZZWFYwYUc5eWFYUjVJanA3SW5SNWNHVWlPaUp6ZEhKcGJtY2lmU3dpYVhOemRXRnVZMlZmWkdGMFpTSTZleUowZVhCbElqb2ljM1J5YVc1bkluMHNJbVY0Y0dseWVWOWtZWFJsSWpwN0luUjVjR1VpT2lKemRISnBibWNpZlgwc0luSmxjWFZwY21Wa0lqcGJYU3dpWVdSa2FYUnBiMjVoYkZCeWIzQmxjblJwWlhNaU9uUnlkV1Y5ZlEiXSwieDVjIjpbIk1JSUIzRENDQVlFQ0ZIQkRXcGtMaTY0ZjVackYweHV5dGo1UElyYnFNQW9HQ0NxR1NNNDlCQU1DTUhBeEN6QUpCZ05WQkFZVEFrZFNNUTh3RFFZRFZRUUlEQVpCZEdobGJuTXhFREFPQmdOVkJBY01CMGxzYkdsemFXRXhFVEFQQmdOVkJBb01DSGQzVjJGc2JHVjBNUkV3RHdZRFZRUUxEQWhKWkdWdWRHbDBlVEVZTUJZR0ExVUVBd3dQZDNkM1lXeHNaWFF0YVhOemRXVnlNQjRYRFRJME1Ea3lOakE0TVRReE1sb1hEVE0wTURreU5EQTRNVFF4TWxvd2NERUxNQWtHQTFVRUJoTUNSMUl4RHpBTkJnTlZCQWdNQmtGMGFHVnVjekVRTUE0R0ExVUVCd3dIU1d4c2FYTnBZVEVSTUE4R0ExVUVDZ3dJZDNkWFlXeHNaWFF4RVRBUEJnTlZCQXNNQ0Vsa1pXNTBhWFI1TVJnd0ZnWURWUVFEREE5M2QzZGhiR3hsZEMxcGMzTjFaWEl3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVF0WTlrVVFGZkRmNmlvY0ZFNHJSdnkzR015WXlwcW1YM1pqbXdVZVhKeTBra2dSVDczQzgrV1BrV05nL3lkSkhDRURETzVYdVJhSWFPSGM5RHBMcE5TTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFEencyN25CcjdFOE42R3FjODN2LzYrOWl6aS9ORVhCS2xvandMSkFlU2xzQUloQU8ySmRqUEV6M2JEMHN0b1dFZzdSRHRyQW04ZHNncnlDeTFXNUJER0NWZE4iXSwiYWxnIjoiRVMyNTYifQ.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJvdy0tc1EwTERHYWxEMEJtZ2VmeWtnOTBJT2FKX1lHZ0RyZTNLMUtwNkY4IiwieSI6Ikp1SjBOX3ZNQ3NrNkdsTVd1SEpVMXlsNVRDQkp0dnpNWjlEMjU3UkJmUFUifX0sInZjdCI6InVybjpjcmVkZW50aWFsOnZpZCIsImp0aSI6InVybjp2aWQ6YjBmNzE3MzgtYzI0Zi00OWVjLThkZTMtOWJhN2YyN2FlYWMyIiwiaXNzdWFuY2VfZGF0ZSI6IjIwMjUtMDEtMjRUMTI6NDc6NDMuMjI4WiIsImV4cGlyeV9kYXRlIjoiMjAyNi0wNC0yMVQwMDowMDowMC4wMDBaIiwiaWF0IjoxNzM3NzIyODYzLCJleHAiOjE3NzY3Mjk2MDAsImlzcyI6Imh0dHBzOi8veW91cmV1ZGkuZGM0ZXUuZXUiLCJzdWIiOiJWckdRbUlYa1pZNVktOUxCWG43TUduU01DT1NOSnVIaTRjSUJHZ01QNkdrIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOlsiQjJPRWsxalNweS02Z0Fmc21pb2Z2ZFZqeFgzSlBoZ0pmQXJLdXdpaXNCQSIsIlNVUnhpMjc3VzlzeWVlY2FHMWZIVDFyUTVCYnhQZkJBYkdpbjRRNDBHT28iLCJmZm9wSTlRczRFZDVFR3o5bm5RbGFfazZ6MnJWODNMXzYxRTNjWXA2OWtjIiwidk5kUWRCTlEyODFpb3N4S204SzB4NzV5WlMybGI1MEtRTndlOVVMNlRHOCIsIncwMzU3YV9uV2ZHaFlpR3ZvVGVTaXhSZzNzRzd0X3hQNmhEQjBaeGRNYkEiXX0.qVUfsWRZxMQsbzMR5kYNvNikJNEBjuEPMQ6npjRRAZrYz_-egFBVq0TivIOHfJ0hcYxIJh3kxIUzHBWjLV9yFQ~WyJyOWtyS1J6S3JVTU5TSXViTlJQOWp3IiwiZ2l2ZW5fbmFtZSIsIlNjYXJsZXR0Il0~WyJOQ2lYekI5ZjJYRWlwU2xtc0dPRWFRIiwiZmFtaWx5X25hbWUiLCJKb2hhbnNzb24iXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6IjA2NWY0NTQ4LTM3NzQtNDJhNS04MjYyLWU5NDhiMjIyNDhkMCIsImF1ZCI6InlvdXJmcmllbmRseXZlcmlmaWVyLmRjNGV1LmV1Iiwic2RfaGFzaCI6ImlfdjJQbUg5NnZ4eGJfbXQ3RmtIdkQ1aEdXeENOamhIdlpzYXlUSlA1alUiLCJpYXQiOjE3Mzc5Njk3Mzl9.4cJbdod2KnKoNAsaIyGlw4ehNl4JAEk9fw6lJqW8Kdq2a65iL9qsVgRSVGO11OuSKX663lUdjnAWA9_glnDUIQ"

const ehic_sd_jwt_adam_driver = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRlZmF1bHRfc2lnbmluZ19rZXlfaWQiLCJ0eXAiOiJ2YytzZC1qd3QiLCJ2Y3RtIjpbImV5SjJZM1FpT2lKRlNFbERRM0psWkdWdWRHbGhiQ0lzSW01aGJXVWlPaUpGU0VsRElpd2laR1Z6WTNKcGNIUnBiMjRpT2lKVWFHbHpJR2x6SUdGdUlFVklTVU1nWkc5amRXMWxiblFnYVhOemRXVmtJR0o1SUhSb1pTQjNaV3hzSUd0dWIzZHVJRVZJU1VNZ1NYTnpkV1Z5SWl3aVpHbHpjR3hoZVNJNlczc2liR0Z1WnlJNkltVnVMVlZUSWl3aWJtRnRaU0k2SWtWSVNVTWlMQ0p5Wlc1a1pYSnBibWNpT25zaWMybHRjR3hsSWpwN0lteHZaMjhpT25zaWRYSnBJam9pYUhSMGNITTZMeTl5WVhjdVoybDBhSFZpZFhObGNtTnZiblJsYm5RdVkyOXRMMlJqTkdWMUwzWmpMems0TXpKaVlqUTVOR1ZqWkRrNE1tTXpZV0UxTm1Wa01XSTFNRFJsTTJFNE9EUmtORFprTWpNdmFXMWhaMlZ6TDJWb2FXTmpZWEprTG5CdVp5SXNJblZ5YVNOcGJuUmxaM0pwZEhraU9pSnphR0V5TlRZdE1USTBZelZtWldFeE5EaGtOVFkxTWpkaVlXRTNOekkxT1RrME1tSTJaV1UxTURVd1pUWXpOV05qT0Raak1qWTRabVEwTWpVNE4yUXdNakpoTmpsak55SXNJbUZzZEY5MFpYaDBJam9pUlVoSlF5QkRZWEprSW4wc0ltSmhZMnRuY205MWJtUmZZMjlzYjNJaU9pSWpNVEl4TURkaklpd2lkR1Y0ZEY5amIyeHZjaUk2SWlOR1JrWkdSa1lpZlN3aWMzWm5YM1JsYlhCc1lYUmxjeUk2VzNzaWRYSnBJam9pYUhSMGNITTZMeTl5WVhjdVoybDBhSFZpZFhObGNtTnZiblJsYm5RdVkyOXRMMlJqTkdWMUwzWmpMems0TXpKaVlqUTVOR1ZqWkRrNE1tTXpZV0UxTm1Wa01XSTFNRFJsTTJFNE9EUmtORFprTWpNdmFXMWhaMlZ6TDJWb2FXTlVaVzF3YkdGMFpTNXpkbWNpTENKMWNta2phVzUwWldkeWFYUjVJam9pYzJoaE1qVTJMV001TURnNVkySXlZemhpT0RRMVlUWTVPVGM0WTJNNVlXUmpNbVExTTJNNE9ESXdOMlZrTldFMU9EWXpPVGxpT1dGbFpHVTRaVEZoT1ROalpETXdOV0VpTENKd2NtOXdaWEowYVdWeklqcDdJbTl5YVdWdWRHRjBhVzl1SWpvaUlpd2lZMjlzYjNKZmMyTm9aVzFsSWpvaUlpd2lZMjl1ZEhKaGMzUWlPaUlpZlgxZGZYMWRMQ0pqYkdGcGJYTWlPbHQ3SW5CaGRHZ2lPbHNpYzI5amFXRnNYM05sWTNWeWFYUjVYM0JwYmlKZExDSmthWE53YkdGNUlqcGJleUpzWVc1bklqb2laVzR0VlZNaUxDSnNZV0psYkNJNklsTnZZMmxoYkNCVFpXTjFjbWwwZVNCT2RXMWlaWElpTENKa1pYTmpjbWx3ZEdsdmJpSTZJbFJvWlNCemIyTnBZV3dnYzJWamRYSnBkSGtnYm5WdFltVnlJRzltSUhSb1pTQkZTRWxESUdodmJHUmxjaUo5WFN3aWMyUWlPaUlpTENKemRtZGZhV1FpT2lKemIyTnBZV3hmYzJWamRYSnBkSGxmY0dsdUluMHNleUp3WVhSb0lqcGJJbU52YlhCbGRHVnVkRjlwYm5OMGFYUjFkR2x2YmlJc0ltbHVjM1JwZEhWMGFXOXVYMk52ZFc1MGNua2lYU3dpWkdsemNHeGhlU0k2VzNzaWJHRnVaeUk2SW1WdUxWVlRJaXdpYkdGaVpXd2lPaUpKYzNOMVpYSWdRMjkxYm5SeWVTSXNJbVJsYzJOeWFYQjBhVzl1SWpvaVZHaGxJR2x6YzNWbGNpQmpiM1Z1ZEhKNUlHOW1JSFJvWlNCRlNFbERJR2h2YkdSbGNpSjlYU3dpYzJRaU9pSWlMQ0p6ZG1kZmFXUWlPaUpwYzNOMVpYSmZZMjkxYm5SeWVTSjlMSHNpY0dGMGFDSTZXeUpqYjIxd1pYUmxiblJmYVc1emRHbDBkWFJwYjI0aUxDSnBibk4wYVhSMWRHbHZibDlwWkNKZExDSmthWE53YkdGNUlqcGJleUpzWVc1bklqb2laVzR0VlZNaUxDSnNZV0psYkNJNklrbHpjM1ZsY2lCSmJuTjBhWFIxZEdsdmJpQkRiMlJsSWl3aVpHVnpZM0pwY0hScGIyNGlPaUpVYUdVZ2FYTnpkV1Z5SUdsdWMzUnBkSFYwYVc5dUlHTnZaR1VnYjJZZ2RHaGxJRVZJU1VNZ2FHOXNaR1Z5SW4xZExDSnpaQ0k2SWlJc0luTjJaMTlwWkNJNkltbHpjM1ZsY2w5cGJuTjBhWFIxZEdsdmJsOWpiMlJsSW4wc2V5SndZWFJvSWpwYkltUnZZM1Z0Wlc1MFgybGtJbDBzSW1ScGMzQnNZWGtpT2x0N0lteGhibWNpT2lKbGJpMVZVeUlzSW14aFltVnNJam9pU1dSbGJuUnBabWxqWVhScGIyNGdZMkZ5WkNCdWRXMWlaWElpTENKa1pYTmpjbWx3ZEdsdmJpSTZJbFJvWlNCSlpHVnVkR2xtYVdOaGRHbHZiaUJqWVhKa0lHNTFiV0psY2lCdlppQjBhR1VnUlVoSlF5Qm9iMnhrWlhJaWZWMHNJbk5rSWpvaUlpd2ljM1puWDJsa0lqb2lhV1JsYm5ScFptbGpZWFJwYjI1ZmJuVnRZbVZ5WDJOaGNtUWlmU3g3SW5CaGRHZ2lPbHNpY0dWeWFXOWtYMlZ1ZEdsMGJHVnRaVzUwSWl3aVpXNWthVzVuWDJSaGRHVWlYU3dpWkdsemNHeGhlU0k2VzNzaWJHRnVaeUk2SW1WdUxWVlRJaXdpYkdGaVpXd2lPaUpGZUhCcGNua2dSR0YwWlNJc0ltUmxjMk55YVhCMGFXOXVJam9pVkdobElHUmhkR1VnWVc1a0lIUnBiV1VnWlhod2FYSmxaQ0IwYUdseklHTnlaV1JsYm5ScFlXd2lmVjBzSW5Oa0lqb2lJaXdpYzNablgybGtJam9pWlhod2FYSjVYMlJoZEdVaWZWMHNJbk5qYUdWdFlWOTFjbXdpT2lJaUxDSnpZMmhsYldGZmRYSnNJMmx1ZEdWbmNtbDBlU0k2SWlJc0ltVjRkR1Z1WkhNaU9pSWlMQ0psZUhSbGJtUnpJMmx1ZEdWbmNtbDBlU0k2SWlKOSJdfQ.eyJfc2QiOlsiNE91cnpQVl9BX1dPaDR0MHU4OUpWOWoyY1dHQ0tXTHY3YW5qRHJha19tUSIsIkRrWWZuZVNqbXRhLU14OHZzYXp3NnRlam1TRS1jMzZnVUduQjA1NVVyTU0iLCJyZldLbXVRdzgyemw3SHhPc3Flb0oxaDAwNTk5WXRVVS1nSmh1TkU1d0w4IiwiT2IyOVdnZE5ON3psR2hINWJyYmNqRC16Zk9yOTZuS0pRcDROVkZzTUVKYyIsIlJyLXhqdnFLckRvdFlTcTRzN0RhTEgxNUs1blMyNC0wVGNoWnpmWUpIQ2ciXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImtpZCI6ImRlZmF1bHRfc2lnbmluZ19rZXlfaWQiLCJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkNkajd6MHFna2hpRHFVY2RRTFBINGMzaDNpY1Q0Yk9QNWFJampVX2h1LUkiLCJ5IjoiRnlfdnozd25jNXQxb1dJTVh0YVNoZXhVZGRZLUV5blJPZGFpRFJ0ZGY2MCJ9fSwiZXhwIjoxNzcwMjA5ODg1LCJpc3MiOiJodHRwczovL2lzc3Vlci5zdW5ldC5zZSIsIm5iZiI6MTczODY3Mzg4NSwidmN0IjoiRUhJQ0NyZWRlbnRpYWwifQ.WYcIyj850e8OBfDss5As9Jf1tauwXeqRSLWEO2B_hxE6RBtfGRmnK7W8MEkpRpxjdSM731UkDVI7ddXDY0Ygig~WyI3SkZKLUJCQjlPOC1mNjVlcHB5RmlRIiwic3ViamVjdCIseyJkYXRlX29mX2JpcnRoIjoiMTk4OC0wOS0yNyIsImZhbWlseV9uYW1lIjoiRHJpdmVyIiwiZm9yZW5hbWUiOiJBZGFtIn1d~WyJwUUhsd1h6bVhCRl96Y2FZZWlVcUZBIiwic29jaWFsX3NlY3VyaXR5X3BpbiIsIjI5ODk5NTQ4Il0~WyJ6R0ctWndZd1l1Q0VNZkFlbjV2RC1RIiwicGVyaW9kX2VudGl0bGVtZW50Iix7ImVuZGluZ19kYXRlIjoiMjAyNi0wNC0xMiIsInN0YXJ0aW5nX2RhdGUiOiIyMDIzLTA5LTEyIn1d~WyJ3RW9BWmtJMUJVS1lvYXhMNHFZaUlnIiwiZG9jdW1lbnRfaWQiLCI4MDI0NjgwMjQ2MDAwMzkyOTY5MSJd~WyJKX21wTTZGMEktRlJ6WEl6QXJmNWNnIiwiY29tcGV0ZW50X2luc3RpdHV0aW9uIix7Imluc3RpdHV0aW9uX2NvdW50cnkiOiJGUiIsImluc3RpdHV0aW9uX2lkIjoiQ0xFSVNTIiwiaW5zdGl0dXRpb25fbmFtZSI6Ikdyb3VwZSBDYWlzc2UgZGVzIETDqXDDtHRzIGFzc2lzdGVkIGJ5IHRoZSBDZW50cmUgb2YgRXVyb3BlYW4gYW5kIEludGVybmF0aW9uYWwgTGlhaXNvbnMgZm9yIFNvY2lhbCBTZWN1cml0eSJ9XQ~"

func TestVPToken_Process(t *testing.T) {
	ecdsaP256Private, ecdsaP256Public, err := generateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	vp_token_ehic_adam_driver, err := build_vp_jws_token_with_jwt_vc_credentials(ehic_sd_jwt_adam_driver, jwt.SigningMethodES256, ecdsaP256Private, "did:example:issuer#key-1")
	if err != nil {
		t.Fatal(err)
	}
	vp_token_ehic_adam_driver_JWE, err := encryptToJWE([]byte(vp_token_ehic_adam_driver), ecdsaP256Public)

	vp_token_with_1_jwt_vc, err := build_vp_jws_token_with_jwt_vc_credentials(pid_sd_vc_jwt_with_selective_disclosures_and_holder_binding, jwt.SigningMethodES256, ecdsaP256Private, "did:example:issuer#key-1")
	if err != nil {
		t.Fatal(err)
	}
	vp_token_with_2_ldp_vc, err := build_vp_jws_token_with_ldp_vc_credentials(jwt.SigningMethodES256, ecdsaP256Private, "did:example:issuer#key-1")
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		RawToken string
		//ValidationResults map[string]bool
	}
	tests := []struct {
		name            string
		fields          fields
		holderPublicKey interface{}
		jwePrivateKey   interface{}
		issuerPublicKey interface{}
		wantErr         bool
	}{
		//TODO bryt ut till till en testcase builder för att enkelt testa massa olika varianter
		{
			name: "Generated vp token ehic adam driver as JWE",
			fields: fields{
				RawToken: vp_token_ehic_adam_driver_JWE,
			},
			holderPublicKey: ecdsaP256Public,
			jwePrivateKey:   ecdsaP256Private,
			issuerPublicKey: ecdsaP256Public,
			wantErr:         false,
		},
		{
			name: "Generated vp token ehic adam driver",
			fields: fields{
				RawToken: vp_token_ehic_adam_driver,
			},
			holderPublicKey: ecdsaP256Public,
			wantErr:         false,
		},
		{
			name: "Generated vp token with 1 hardcoded jwt_vc (has wrong issuer)",
			fields: fields{
				RawToken: vp_token_with_1_jwt_vc,
			},
			holderPublicKey: ecdsaP256Public,
			wantErr:         true,
		},
		{
			name: "Generated vp token with 2 ldp_vc (format not supported yet)",
			fields: fields{
				RawToken: vp_token_with_2_ldp_vc,
			},
			holderPublicKey: ecdsaP256Public,
			wantErr:         true,
		},
		{
			name: "Hardcoded vp_token_1",
			fields: fields{
				RawToken: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly93YWxsZXQuZXhhbXBsZS5jb20iLCJpYXQiOjE3MzgwNjU4OTksImV4cCI6MTczODE1MjI5OSwibm9uY2UiOiJyYW5kb21seS1nZW5lcmF0ZWQtbm9uY2UiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IkRvZSIsImRlZ3JlZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgaW4gQ29tcHV0ZXIgU2NpZW5jZSJ9LCJwcm9vZiI6eyJ0eXBlIjoiRWQyNTUxOVNpZ25hdHVyZTIwMTgiLCJjcmVhdGVkIjoiMjAyNS0wMS0wMVQxMDowMDowMFoiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJodHRwczovL2V4YW1wbGUuY29tL2tleXMvMTIzIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwiY2hhbGxlbmdlIjoicmFuZG9tLWNoYWxsZW5nZS12YWx1ZSIsImRvbWFpbiI6ImV4YW1wbGUuY29tIiwicHJvb2ZWYWx1ZSI6ImJhc2U2NHVybC1lbmNvZGVkLXByb29mLXZhbHVlIn19LHsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRyaXZlckxpY2Vuc2UiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6IkFsaWNlIERvZSIsImxpY2Vuc2VfbnVtYmVyIjoiMTIzNDU2NzgifSwicHJvb2YiOnsidHlwZSI6IkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiY3JlYXRlZCI6IjIwMjUtMDEtMDFUMTE6MDA6MDBaIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiaHR0cHM6Ly9kbXYuZXhhbXBsZS5jb20va2V5cy80NTYiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJjaGFsbGVuZ2UiOiJhbm90aGVyLWNoYWxsZW5nZS12YWx1ZSIsImRvbWFpbiI6ImRtdi5leGFtcGxlLmNvbSIsInByb29mVmFsdWUiOiJiYXNlNjR1cmwtZW5jb2RlZC1wcm9vZi12YWx1ZSJ9fV19fQ.UntYvN8d2A4nOffSKx7qa5A76Kn7uaCjpt0k8gRAXID7epFoSHlFZHNO5qJ8E-6kD3xYuoKp5uOYQr7Qpak0ZQ`,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp, err := NewVPToken(tt.fields.RawToken)
			vp.holderPublicKey = tt.holderPublicKey
			vp.jwePrivateKey = tt.jwePrivateKey
			vp.issuerPublicKey = tt.issuerPublicKey
			if err != nil {
				t.Fatal(err)
			}

			if err := vp.Process(FULL_VALIDATION); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			//TODO lägg till asserts
		})
	}
}

func build_vp_jws_token_with_jwt_vc_credentials(vcJWT string, signingMethod jwt.SigningMethod, holderPublicKey interface{}, keyID string) (string, error) {
	now := time.Now()

	var vcList []string
	if strings.TrimSpace(vcJWT) == "" {
		vcList = []string{}
	} else {
		vcList = []string{vcJWT}
	}

	claims := jwt.MapClaims{
		"iss": "did:example:myprivatewallet",
		"aud": "did:example:sunetverifier",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute * 5).Unix(),
		"vp": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/v2",
			},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": vcList,
		},
		"presentation_submission": map[string]interface{}{
			"id":            "ae1773e-3e19-4032-a1c2-a6b69087e5b2",
			"definition_id": "vp_definition_1",
			"descriptor_map": []map[string]interface{}{
				{
					"id":     "pid_input",
					"path":   "$.vp.verifiableCredential[0]",
					"format": "jwt_vc",
				},
			},
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "JWS"

	return signJWT(signingMethod, token, holderPublicKey)
}

func build_vp_jws_token_with_ldp_vc_credentials(signingMethod jwt.SigningMethod, holderPublicKey interface{}, keyID string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss": "did:example:issuer",
		"aud": "did:example:verifier",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute * 5).Unix(),
		"vp": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/v2",
			},
			"type": []string{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{
				map[string]interface{}{
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://w3id.org/security/v2",
					},
					"id":           "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
					"type":         []string{"VerifiableCredential", "UniversityDegreeCredential"},
					"issuer":       "did:example:issuer",
					"issuanceDate": "2020-03-10T04:24:12.164Z",
					"credentialSubject": map[string]interface{}{
						"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
						"degree": map[string]interface{}{
							"type": "BachelorDegree",
							"name": "Bachelor of Science and Arts",
						},
					},
					"proof": map[string]interface{}{
						"type":               "Ed25519Signature2018",
						"created":            "2023-01-29T08:00:00Z",
						"verificationMethod": "did:example:issuer#key-1",
						"jws":                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..",
					},
				},
				map[string]interface{}{
					"@context": []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://w3id.org/security/v2",
					},
					"id":           "urn:uuid:d2760df0-c454-4b44-8795-85dda4e126c7",
					"type":         []string{"VerifiableCredential", "DriverLicenseCredential"},
					"issuer":       "did:example:issuer2",
					"issuanceDate": "2022-01-01T00:00:00Z",
					"credentialSubject": map[string]interface{}{
						"id":         "did:example:ebfeb1f712ebc6f1c276e12ec21",
						"givenName":  "Jane",
						"familyName": "Doe",
						"birthDate":  "1995-05-10",
					},
					"proof": map[string]interface{}{
						"type":               "Ed25519Signature2018",
						"created":            "2023-01-29T09:00:00Z",
						"verificationMethod": "did:example:issuer2#key-1",
						"jws":                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..",
					},
				},
			},
		},
		"presentation_submission": map[string]interface{}{
			"id":            "ae23773e-3e39-4032-a1c2-a6b69087e5b6",
			"definition_id": "vp_definition_2",
			"descriptor_map": []map[string]interface{}{
				{
					"id":     "degree_input",
					"path":   "$.vp.verifiableCredential[0]",
					"format": "ldp_vc",
				},
				{
					"id":     "license_input",
					"path":   "$.vp.verifiableCredential[1]",
					"format": "ldp_vc",
				},
			},
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "JWS"

	return signJWT(signingMethod, token, holderPublicKey)
}

func signJWT(signingMethod jwt.SigningMethod, token *jwt.Token, holderPublicKey interface{}) (string, error) {
	switch signingMethod.(type) {
	case *jwt.SigningMethodECDSA:
		return token.SignedString(holderPublicKey.(*ecdsa.PrivateKey))
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return token.SignedString(holderPublicKey.(*rsa.PrivateKey))
	case *jwt.SigningMethodEd25519:
		return token.SignedString(holderPublicKey.(ed25519.PrivateKey))
	case *jwt.SigningMethodHMAC:
		return token.SignedString(holderPublicKey.([]byte))
	default:
		return "", fmt.Errorf("unknown signingmethod")
	}
}

func generateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateECDSAKeyPairSecp256k1() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateEdDSAKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func generateHMACKey() ([]byte, error) {
	hmacKey := make([]byte, 32) // 256-bit HMAC-nyckel
	_, err := rand.Read(hmacKey)
	if err != nil {
		return nil, err
	}
	return hmacKey, nil
}

func encryptToJWE(jwtString []byte, publicKey *ecdsa.PublicKey) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM, // content encryption alg
		jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW, // key encryption
			Key:       publicKey,
		},
		&jose.EncrypterOptions{
			Compression: jose.DEFLATE,
		},
	)
	if err != nil {
		return "", fmt.Errorf("Failed to create JWE encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(jwtString)
	if err != nil {
		return "", fmt.Errorf("Failed to encrypt JWT to JWE: %w", err)
	}

	return jwe.CompactSerialize()
}

/* Below is a readable form for vp_token_1 in the test:
{
  "header": {
	"alg": "ES256",
	"typ": "JWT"
  },
  "payload": {
	"aud": "https://verifier.example.com",
	"iss": "https://wallet.example.com",
	"iat": 1738065899,
	"exp": 1738152299,
	"nonce": "randomly-generated-nonce",
	"vp": {
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/ns/credentials/examples/v1"
	  ],
	  "type": ["VerifiablePresentation"],
	  "verifiableCredential": [
		{
		  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
		  "credentialSubject": {
			"given_name": "Alice",
			"family_name": "Doe",
			"degree": "Bachelor of Science in Computer Science"
		  },
		  "proof": {
			"type": "Ed25519Signature2018",
			"created": "2025-01-01T10:00:00Z",
			"verificationMethod": "https://example.com/keys/123",
			"proofPurpose": "assertionMethod",
			"challenge": "random-challenge-value",
			"domain": "example.com",
			"proofValue": "base64url-encoded-proof-value"
		  }
		},
		{
		  "type": ["VerifiableCredential", "DriverLicense"],
		  "credentialSubject": {
			"name": "Alice Doe",
			"license_number": "12345678"
		  },
		  "proof": {
			"type": "Ed25519Signature2018",
			"created": "2025-01-01T11:00:00Z",
			"verificationMethod": "https://dmv.example.com/keys/456",
			"proofPurpose": "assertionMethod",
			"challenge": "another-challenge-value",
			"domain": "dmv.example.com",
			"proofValue": "base64url-encoded-proof-value"
		  }
		}
	  ]
	}
  }
}
*/
