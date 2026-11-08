# attestation_checker

## Jenkins / Quadlet デプロイ

Jenkins から `build/jenkins.sh` を実行すると、Podman イメージをビルドし、ユーザー単位の systemd Quadlet でアプリケーションをデプロイします。Gunicorn が Flask アプリをコンテナ内の `8080` 番ポートで配信し、ホストの `8083` 番ポートに公開します。

### Jenkins 実行環境

- Jenkins エージェントに Podman、systemd user service、`envsubst`（gettext）がインストールされていること
- Jenkins の実行ユーザーが rootless Podman を利用でき、`systemctl --user` を実行できること
- Jenkins 実行ユーザーの linger を有効にして、Jenkins のログアウト後も user systemd を稼働させること（例: `sudo loginctl enable-linger jenkins`）
- Jenkins の環境変数に `RP_ID` を設定すること（WebAuthn の Relying Party ID。例: `example.com`）

### デプロイ方法

Jenkins ジョブのワークスペースで次を実行します。

```bash
bash build/jenkins.sh
```

Quadlet ユニットは `$HOME/.config/containers/systemd/attestation-checker/` に配置され、`attestation-checker-pod.service` として起動します。変更後のユニットは `systemctl --user daemon-reload` で読み込み、Jenkins 実行ユーザーの systemd が管理します。
