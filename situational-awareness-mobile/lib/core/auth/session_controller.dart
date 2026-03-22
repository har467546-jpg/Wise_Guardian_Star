import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../shared/models/app_models.dart';
import '../network/api_client.dart';
import '../storage/app_storage.dart';

class SessionController extends AsyncNotifier<SessionSnapshot> {
  @override
  Future<SessionSnapshot> build() async {
    final token = await ref.read(appStorageProvider).readToken();
    if (token == null || token.isEmpty) {
      return const SessionSnapshot.signedOut();
    }
    return SessionSnapshot.signedIn(
      token: token,
      role: decodeRoleFromToken(token),
    );
  }

  Future<void> signIn({
    required String username,
    required String password,
  }) async {
    state = const AsyncLoading();
    final auth = await ref.read(apiClientProvider).login(username: username, password: password);
    await _persist(auth.accessToken);
  }

  Future<void> bootstrapAdmin({
    required String username,
    required String email,
    required String password,
  }) async {
    state = const AsyncLoading();
    final auth = await ref.read(apiClientProvider).bootstrapAdmin(
          username: username,
          email: email,
          password: password,
        );
    await _persist(auth.accessToken);
  }

  Future<void> signOut() async {
    state = const AsyncLoading();
    await ref.read(appStorageProvider).clearToken();
    state = const AsyncData(SessionSnapshot.signedOut());
  }

  Future<void> expireSession() async {
    await ref.read(appStorageProvider).clearToken();
    state = const AsyncData(SessionSnapshot.signedOut());
  }

  Future<void> _persist(String token) async {
    await ref.read(appStorageProvider).writeToken(token);
    state = AsyncData(
      SessionSnapshot.signedIn(
        token: token,
        role: decodeRoleFromToken(token),
      ),
    );
  }
}

final sessionControllerProvider = AsyncNotifierProvider<SessionController, SessionSnapshot>(
  SessionController.new,
);
