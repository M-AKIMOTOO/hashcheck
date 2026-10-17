# hashcheck v2.9 (Python 3.10+)

`hashcheck` は **ファイル、ディレクトリ、指定 byte range、または固定サイズ block ごとの SHA-256** を計算し、圧縮バイナリ manifest (`.hash`) へ保存するツールです。

転送機能や stdin/stdout の pass-through 機能は持ちません。巨大な観測ファイルを分割転送する場合も、転送経路とは独立して必要な byte range だけを読みます。

対応環境:

- Python 3版: Python 3.10以降が動作する Linux、macOS、Windows 10/11
- C版: Linux（Scientific Linux 6 / RHEL 6 系を含む）、macOS、Windows 10/11

通常ファイルの SHA-256 は sha256sum と同じ SHA-256 です。生成時には最上位対象ごとの値も標準出力へ表示します。ディレクトリでは tree hash、range では対象 byte 範囲の値、block では各 block の値と相対 offset を表示します。

表示例:

    SHA-256  <64桁の16進値>  <対象名>
    Wrote <manifest名> : ...

## Python 3版の実行

Python 3.10以降で動作し、標準ライブラリ以外のパッケージは必要ありません。

    python3 hashcheck.py FILE_OR_DIRECTORY
    python3 hashcheck.py --help

C 版は make install で ~/bin/hashcheck にインストールできます。インストール先を変更する場合は BINDIR=/path/to/bin make install を使います。Python 版は python3 hashcheck.py で実行できます。

## C版をビルドする場合

Makefile は C 版のビルド・インストール・clean のみを扱います。Python 版と Zig 版は、それぞれ下記の方法で直接実行してください。C 版のビルドは:

    make


## SHA-256 の高速化

C版ではLinux上で通常ファイルと byte range の SHA-256 に、利用可能なら OS の `libcrypto` (OpenSSL) を実行時に自動利用します。CPU の SHA 命令を利用できる環境では、内蔵 scalar SHA-256 より大幅に高速です。

対応する `libcrypto` が見つからない場合は、自動的に内蔵 SHA-256 にフォールバックします。manifest 形式や SHA-256 の値はどちらでも同一です。OpenSSL の開発ヘッダは不要ですが、Scientific Linux 6 を含む古い Linux では `dlopen()` 用にリンク時の `-ldl` が必要です。

高速 backend を意図的に無効化する場合だけ:

```sh
gcc -O3 -std=gnu99 -Wall -Wextra -D_FILE_OFFSET_BITS=64 -DHC_NO_LIBCRYPTO hashcheck.c -o hashcheck
```

### Windows 11 x86_64 / Zig

```bat
zig cc -O3 -std=c11 -target x86_64-windows-gnu -municode hashcheck.c -s -o hashcheck.exe
```

## Help

引数なしでは何も hash せず、ヘルプを表示します。

```sh
hashcheck
```

誤って巨大なカレントディレクトリを hash し始めることはありません。


## コマンドラインオプション

```text
-o FILE             出力先を指定。通常は .hash、--mksh 時は .sh。
-c, --compare       2つの manifest を明示的に比較。
--offset N          range hash の開始 byte offset。--length と組で使用。
--length N          range hash で読む byte 数。--offset と組で使用。
--block N           対象データを N byte ごとの独立した SHA-256 block に分割。
--every N           N 個ごとに hash (default: 10)。--mksh では N 秒ごと。
--exclude RULE      ファイルを拡張子 (.tmp)、basename (name.tmp)、または root からの相対パス (sub/name.tmp) で除外。繰り返し指定可能。
--mksh DRG          DRG の $SKED から range hash 用 shell script を生成。
--log LOG           --mksh で必須。REQRECSTART / RECSTART から記録開始時刻を取得。
-h, --help          ヘルプ表示。
```

`--offset` / `--length` は byte 単位です。

## 1. ファイル

```sh
hashcheck a.txt
```

生成:

```text
a.txt.hash
```

確認:

```sh
hashcheck a.txt.hash
```

ファイル本体の SHA-256 は `sha256sum` と一致します。

```sh
sha256sum a.txt
hashcheck a.txt.hash
```

## 2. ディレクトリ

```sh
hashcheck I26285TR/
```

生成:

```text
I26285TR.hash
```

manifest には root directory、全 subdirectory、全 regular file、POSIX symlink の hash が保存されます。

ファイルを除外する場合は `--exclude` を繰り返し指定できます。`.tmp` は拡張子、`Thumbs.db` は basename、`cache/tmp.bin` は root からの相対パスです。dotfile を basename で指定する場合は `file:.gitignore` を使います。除外したファイルはディレクトリの tree hash にも含まれません。

```sh
hashcheck --exclude .tmp --exclude Thumbs.db --exclude cache/tmp.bin I26285TR/
```

ディレクトリ自身の hash は、名前順に並べた直接の子要素の

```text
child type + UTF-8 child name + child SHA-256
```

から再帰的に計算します。

## 3. 任意 byte range

巨大ファイル全体を hash する必要がない場合は:

```sh
hashcheck --offset OFFSET --length LENGTH FILE
```

`OFFSET` と `LENGTH` は **byte 単位**です。

例:

```sh
hashcheck --offset 100000000 --length 300000000 observation.vdif
```

これは:

```text
observation.vdif の byte 100000000 から
300000000 byte だけ読む
```

という意味です。

切り出しファイルは作りません。

デフォルト出力名:

```text
observation.vdif.100000000+300000000.hash
```

出力名を指定する場合:

```sh
hashcheck -o YAMAGU32_2026283045600.hash \
    --offset 100000000 --length 300000000 observation.vdif
```

manifest を開くと range も確認できます。

```text
range offset : 100000000 bytes
range length : 300000000 bytes
```

### dd と同じ範囲になることの確認

例えば:

```sh
dd if=observation.vdif \
   bs=1 iflag=skip_bytes,count_bytes \
   skip=100000000 count=300000000 status=none \
   > received.raw
```

に対して:

```sh
hashcheck --offset 100000000 --length 300000000 observation.vdif
hashcheck received.raw
hashcheck observation.vdif.100000000+300000000.hash received.raw.hash
```

が

```text
Result : IDENTICAL
```

なら、指定した source range と `received.raw` は byte-for-byte で一致しています。

range manifest と通常ファイル manifest の最上位ファイル名は一致する必要がありません。1 root manifest 同士では最上位名を除いて内容を比較するためです。

range の OFFSET は provenance 情報として manifest に保存されます。比較判定そのものは、転送データとして重要な **SHA-256 と byte length** を使用します。


## 4. 連続 block hash

ファイルまたは range を一定 byte 数ごとに区切り、各 block を独立して SHA-256 にできます。

```sh
hashcheck --block 256000000 FILE
```

指定 range の中だけを block 化する場合:

```sh
hashcheck -o scan.hash \
  --offset 15360000000 \
  --length 153600000000 \
  --block 256000000 \
  --every 1 \
  observation.vdif
```

`1 s = 256000000 byte` の観測データなら、上の例は 600 秒 scan を 600 個の独立した 1 秒 SHA-256 にします (`--every 1`)。

manifest の表示例:

```text
range offset : 15360000000 bytes
range length : 153600000000 bytes
block size   : 256000000 bytes

BLOCK  <SHA-256>   256000000  +00000000000000000000
BLOCK  <SHA-256>   256000000  +00000000000256000000
BLOCK  <SHA-256>   256000000  +00000000000512000000
...
```

BLOCK の末尾は、選択した range の先頭からの相対 byte offset です。そのため、元巨大ファイルの scan range と、受信後の scan `.raw` を同じ `--block` サイズと `--every` 間隔で hash すると直接比較できます。

送信元:

```sh
hashcheck -o source.hash \
  --offset OFFSET --length LENGTH \
  --block 256000000 --every 1 original.vdif
```

受信側:

```sh
hashcheck -o received.hash --block 256000000 --every 1 received.raw
```

比較:

```sh
hashcheck source.hash received.hash
```

差がある場合は、例えば:

```text
CHANGED   +00000000000256000000
```

のように、どの 1 秒 block が異なるか分かります。

`--every N` は N 個ごとの block だけを読みます。既定値は 10 なので、600 秒 scan では約 60 秒分を hash します。全 block を処理するには `--every 1` を指定します。サンプルは各 range の先頭から数え、manifest には元の相対 offset を記録します。

## 5. DRG から 1 秒 block hash shell script を生成

観測 DRG の `$SKED` と記録開始ログから、scan ごとの 1 秒 block hash 用 shell script を生成できます。

```sh
hashcheck --mksh I26289X.DRG --log i26289x_ch3_ymg34cl.log
```

全秒を hash する場合は `--every 1` を指定します。省略時は 10 秒ごとに 1 秒分だけを読みます:

```sh
hashcheck --mksh I26289X.DRG --log i26289x_ch3_ymg34cl.log --every 1
```

記録開始時刻は `--log` から必ず取得します。ログ内に `REQRECSTART` または `RECSTART` が無い場合は生成を拒否します。

データレートは固定で:

```text
1 s = 256000000 bytes
```

各 scan に対して生成されるコマンドは:

```sh
hashcheck -o "${PREFIX}_YYYYDOYhhmmss.hash" \
  --offset OFFSET \
  --length SCAN_BYTES \
  --block 256000000 \
  --every 10 \
  "$INPUT"
```

です。省略時は各 scan の 0 秒目、10 秒目、20 秒目というように hash し、残りの byte は seek で飛ばします。`--every 1` なら全秒を hash します。scan ごとの `hashcheck` 起動は 1 回です。

生成 shell script:

```sh
./hashcheck_I26289X.sh ORIGINAL.vdif YAMAGU34
```

出力例:

```text
YAMAGU34_2026289054300.hash
YAMAGU34_2026289055000.hash
...
```

## 6. manifest の確認・比較

```sh
hashcheck FILE.hash
hashcheck A.hash B.hash
```

比較結果:

```text
Result : IDENTICAL
```

または block 単位で:

```text
CHANGED   +00000000000256000000
Summary: SAME=599 CHANGED=1 ...
Result : DIFFERENT
```

## 注意点

- SHA-256 はファイルの raw byte 列に対して計算します。
- `--offset`, `--length`, `--block` はすべて byte 単位です。
- `--block` は block ごとに独立した SHA-256 を作るため、通常のファイル全体 SHA-256 とは別物です。
- block manifest 同士を比較するときは同じ block size と `--every` 間隔を使用してください。
- `--mksh` では block size は常に 256000000 byte (= 1 秒) です。`--every N` は各 scan の先頭から N 秒ごとに 1 block を hash します (default: 10)。
- timestamp、permission、uid/gid、元の絶対 PATH は比較対象ではありません。
- manifest 自身にも SHA-256 があり、破損時は `manifest SHA : FAILED` になります。
- v1/v2 manifest の読み込み互換性は維持します。

## Progress display

Long file/range/block hashing shows progress on stderr, including percent complete, processed/total bytes, speed, ETA, and block count when `--block` is used.
# hashcheck
