// Pure-parsing tests for the store API models — no native library needed
// (they exercise the same JSON the mock store / real store returns).
import 'package:snapstore_auth/snapstore_auth.dart';
import 'package:test/test.dart';

void main() {
  test('AccountInfo.fromJson parses the whoami shape', () {
    final a = AccountInfo.fromJson('''
    {
      "id": "DEADBEEF1234",
      "email": "mock@example.com",
      "username": "mockuser",
      "display_name": "Mock User",
      "permissions": ["package_access", "package_push"],
      "channels": ["16"],
      "expires": "2026-10-15T12:00:00+00:00"
    }
    ''');
    expect(a.id, 'DEADBEEF1234');
    expect(a.email, 'mock@example.com');
    expect(a.permissions, contains('package_push'));
  });

  test('BrandStore.parseAll reads id/name/roles', () {
    final stores = BrandStore.parseAll([
      {'id': 'ubuntu', 'name': 'Ubuntu', 'roles': ['owner']},
      {'id': 'mock-brand', 'name': 'Mock Brand', 'roles': ['admin']},
    ]);
    expect(stores, hasLength(2));
    expect(stores.first.isGlobal, isTrue);
    expect(stores.last.name, 'Mock Brand');
  });

  test('RegisteredKey.parseAll reads name + sha3-384', () {
    final keys = RegisteredKey.parseAll([
      {'name': 'k1', 'public-key-sha3-384': 'aa' * 24},
    ]);
    expect(keys, hasLength(1));
    expect(keys.first.name, 'k1');
  });

  test('SnapstoreAuthError.from parses http status + detail', () {
    final e = SnapstoreAuthError.from(
        '{"kind":"http","detail":"macaroon is expired","status":401}');
    expect(e.kind, 'http');
    expect(e.httpStatus, 401);
  });
}
