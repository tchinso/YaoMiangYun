# Yao VPN

Windows 10/11 x64용 작은 VPN ON/OFF 앱입니다. 구독에서 VLESS, Hysteria2, AnyTLS 연결 정보만 읽고, 고정한 공식 sing-box 1.14.4 코어로 시스템 TUN을 만듭니다.

## 사용

1. `artifacts/YaoVPN/YaoVPN.exe`를 실행합니다. 폴더 안의 `core`와 런타임 파일도 함께 유지하세요.
2. HTTPS 구독 주소를 넣고 **구독 불러오기 / 새로고침**을 누릅니다. 이 컴퓨터에 준비한 구독은 암호화된 로컬 캐시에서 자동으로 불러옵니다.
3. 서버를 고르고 전원 버튼을 누릅니다. Windows 관리자 권한 창을 승인하면 TUN 연결과 HTTPS 응답을 확인한 뒤 **ON**으로 표시합니다.
4. 다시 누르면 **OFF**로 돌아갑니다. 창을 닫아도 VPN 연결을 종료합니다. 앱을 다시 실행해도 자동 연결하지 않습니다.

연결 중에는 IPv4·IPv6 시스템 터널과 암호화 DNS를 사용합니다. VPN 서버 자체에 대한 연결 준비 트래픽은 직접 나갑니다. 서버의 TCP/UDP 지원·상태·구독 만료에 따라 연결 가능 여부가 달라집니다. 이 앱은 모든 IP 프로토콜이나 임의의 다른 VPN 구독 형식을 지원하는 제품은 아닙니다.

## 보안

- 공급자 프로그램, 플러그인, 스크립트, 루트 인증서를 설치하지 않습니다.
- 공급자 라우팅·DNS·다운로드·파일 설정을 버리고 앱에서 새 설정을 만듭니다. TLS 인증서 검증을 끄는 서버는 거부합니다.
- 코어 SHA-256을 실행 전에 확인합니다. 구독 URL과 인증정보는 `%LOCALAPPDATA%\YaoVPN`에 DPAPI로 암호화해 저장하며 소스나 로그에 기록하지 않습니다.
- 일반 화면은 관리자 권한을 사용하지 않습니다. VPN 연결을 위한 별도 프로세스만 UAC 권한을 요청합니다.

**악성코드 감염 불가능을 보장하지는 않습니다.** 코어·Windows의 취약점이나 직접 실행한 악성 파일은 별도 위험입니다. **영구 킬 스위치는 없습니다.** VPN이 예기치 않게 꺼지면 일반 인터넷으로 돌아갈 수 있습니다. 상세한 범위는 [SECURITY.md](SECURITY.md)를 확인하세요.

## 소스에서 빌드

Windows x64와 .NET 10 SDK가 필요합니다. 외부 NuGet 패키지는 사용하지 않습니다.

```powershell
./scripts/Build.ps1
# SDK가 PATH에 없으면:
./scripts/Build.ps1 -Dotnet 'C:\path\to\dotnet.exe'
```

빌드는 공식 릴리스의 고정 SHA를 검증하고 코어를 준비한 뒤, 보안 회귀 테스트와 자체 런타임을 포함한 실행 폴더를 만듭니다. 원격 PowerShell 스크립트를 받아 실행하지 않습니다.

```powershell
dotnet run --project tests/YaoVpn.Tests -c Release
```

개발용 `--check-private` / `--live` 검증은 현재 Windows 사용자의 암호화된 `bootstrap.dpapi`가 있을 때만 사용합니다. `--live`는 로컬 SOCKS 포트로 실제 서버 연결과 HTTPS 출구를 확인하며 시스템 라우트를 바꾸지 않습니다. 따라서 이 검증만으로 관리자 TUN·DNS 누출·IPv6 동작을 검증했다고 간주하지 않습니다.

## 제거와 문제 해결

앱에서 OFF 후 창을 닫고 앱 폴더를 삭제하면 됩니다. 자동 시작·Windows 서비스·업체 앱을 등록하지 않습니다. 저장된 구독도 지우려면 앱 종료 후 `%LOCALAPPDATA%\YaoVPN`을 삭제합니다. 인증정보가 들어 있으므로 이 폴더를 공유하지 마세요. 연결 실패 시 다른 서버를 고르거나 구독을 갱신하세요. Windows 보안 기능이나 인증서 검증을 끄지 마세요.

GPL-3.0. 제3자 권리와 배포 조건은 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)를 참고하세요.
