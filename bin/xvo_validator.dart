import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    print("INVALID: No file path provided.");
    exit(1);
  }

  final filePath = args[0];
  final file = File(filePath);

  if (!file.existsSync()) {
    print("INVALID: File not found.");
    exit(1);
  }

  final lines = file.readAsLinesSync();
  final contentBuffer = StringBuffer();
  final signatureHexBuffer = StringBuffer();

  for (final line in lines) {
    if (line.isEmpty) continue; 
    
    if (line.startsWith('G')) {
      signatureHexBuffer.write(line.substring(1));
    } else {
      contentBuffer.write(line);
      contentBuffer.write('\r\n');
    }
  }

  final contentStr = contentBuffer.toString();
  final signatureHex = signatureHexBuffer.toString();

  if (signatureHex.isEmpty) {
    print("INVALID: No G-record signature found.");
    exit(1);
  }

  final sigBytes = _hexToBytes(signatureHex);

  // --- INSERT YOUR PUBLIC KEY HERE ---
  const String publicKeyPem = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNUUJ6ud/YHDPxoWAtS/
p690M29Q7ISr/rSOP0TWnthUndDP0cN/okG8ITaFkipsPvXEN55Oku406UKD1Jfe
mhcGjUZmVNUN+Ucv684ZWcxjqnK+wsvtumaninsmXP4sdRWhBSXVcEpeTFrm67oa
MCAImrlJNoMXw6gxcM6KE2vyeroFwliewOV6pXr9dD7eh63NQF9JgYkqeBZ84B30
XOpClTK4FW/QZkSrh5Qwx1USTOOTD8WUzplv7MA6lGWAJxa+pC1YmB5W7YfmG6GU
Dh6ryDp8auvPoKz+E98EOUeMx8k0aEMZ/ySNF2dAPBGO34NtRf4yWVuQBEVosv+8
twIDAQAB
-----END PUBLIC KEY-----
''';

  try {
    final publicKey = CryptoUtils.rsaPublicKeyFromPem(publicKeyPem);
    final contentBytes = Uint8List.fromList(utf8.encode(contentStr));

    final isValid = CryptoUtils.rsaVerify(
      publicKey,
      contentBytes,
      sigBytes,
      algorithm: 'SHA-256/RSA',
    );

    if (isValid) {
      print("VALID");
      exit(0); 
    } else {
      print("INVALID: G-Record signature does not match flight content.");
      exit(1);
    }
  } catch (e) {
    print("INVALID: Cryptographic processing error. File corrupted.");
    exit(1);
  }
}

Uint8List _hexToBytes(String hexStr) {
  final bytes = <int>[];
  for (int i = 0; i < hexStr.length; i += 2) {
    bytes.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}