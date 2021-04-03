# The Last Resort

The Last Resort is a program that encrypts and decrypts files using a passphrase. Instead of outputting a single encrypted file, it outputs N files, and the original file content can be recovered only after recovering K out of the N files, K <= N.

## The Scenario

If you're following best practices to keep yourself safe online, you probably have two-factor authentication enabled on all of your most important online accounts. However, this also means that you could lose access to those accounts if something happens to your two-factor device.

Suppose that you're using your phone as your 2FA device, and you haven't stored any backup codes (such a pain to keep!) or backed up your 2FA keys somewhere else. What would happen if something happened to your phone? Maybe it gets lost or stolen, or breaks without warning. You could be in for a lot of frustration.

Fortunately, there are ways to prevent your phone from being a single point of failure to accessing all your online accounts. You could use a third-party service such as [Authy](https://authy.com/) or [LastPass Authenticator](https://lastpass.com/auth/) that lets you sync your 2FA codes across multiple devices. That way, as long as you have one device still working, you'll still be able to access your online accounts in the event of a disaster.

But what if all of your electronics are destroyed at once? There are many ways for this to happen. For example, your home could flood or be destroyed in a fire. Or the police could steal all your computers in [an act of political retaliation.](https://www.npr.org/2020/12/08/944200394/florida-agents-raid-home-of-rebekah-jones-former-state-data-scientist) For the sake of argument, let's also say that any backup codes you had were also destroyed in the same disaster. That's where The Last Resort comes in. The Last Resort allows you to regain access to critical information such as your 2FA master key after a major catastrophe when all else has failed.

## Usage

### 0. Download The Last Resort

Download this repository and run `npm install` to download the necessary dependencies.

### 1. Find some trusted contacts

Find some friends and/or family that you trust with your critical data. These people should be geographically distributed so that in the event of a regional catastrophe such as an earthquake or a volcano eruption, you'll still be able to get a hold of enough of them to recover your data. You may want to consider additional steps to defend against someone impersonating you and stealing your data through your trusted contacts, if that's a part of your threat model.

### 2. Encrypt your critical data

Identify the smallet set of data you absolutely need to bootstrap your digital access. For example, let's say you use LastPass to store all your passwords and LastPass Authenticator for all your 2FA codes, and you've enabled 2FA on your LastPass account. In this scenario, knowing your LastPass master password and having your LastPass 2FA master key will grant you access to all of your other accounts. Let's gleefully assume that you'll never forget your LastPass master password. This leaves losing your 2FA master key as a way that you could lose access to your accounts. So that's what we'll back up here. Of course, your situation may vary, and you should determine for yourself what you can't afford to lose.

To start a backup, use the `prepare` function of The Last Resort:

```shell
node cli.js prepare [options]

Options:
  -q, --quorum=QUORUM         Number of recovery files needed to restore the key
  -t, --total=TOTAL           Total number of recovery files to generate
  -i, --input=INPUT           File to encrypt
  -o, --output=OUTPUT         Directory to place recovery files in
      --iterations=ITERATIONS Number of PBKDF2 iterations                        (default: 100000)
  -h, --help                  Show help
```

The options `quorum`, `total`, `input`, and `output` are all required. Set `total` equal to the number of trusted contacts you have. For `quorum`, set it high enough that your contacts wouldn't be able to reach quorum without your consent but not so high that you wouldn't be able to reach enough people in the event of the type of disaster you're preparing for.

You'll be prompted for a password. Use a strong password that you won't forget. Don't reuse your password manager's master password if you can help it, as that weakens the second factor in two-factor authentication.

After running The Last Resort, you'll end up with a bunch of files in your output directory named

```
0.tlr-shard
1.tlr-shard
2.tlr-shard
```

etc., up to the total number of recovery files you specified.

### 3. Send the recovery files to your contacts

Send each of your trusted contacts one of your recovery files through secure, E2E-encrypted channels. Make sure to tell them:

You may want to provide your contacts with an accompanying file with additional instructions, such as:

> X.tlr-shard is a backup of critical data belonging to XXXX XXXXX.
>
> Don't send this file to anyone until they've proven that they are XXXX XXXXX.
>
> Don't upload this file to any cloud storage services unless it is E2E encrypted.

### 4. Recover your files if ever needed

In the unlikely event that you ever need to recover critical data using The Last Resort, reach out to as many trusted contacts as you can and get `QUORUM` recovery files. Then, run The Last Resort again in restore mode.

You should also do a test restore right after creating your recovery files to make sure that you've set up everything correctly.

```shell
node cli.js restore [OPTION] [recovery files...]

Options:
  -o, --output=OUTPUT Where to place the restored file
  -h, --help          Show help
```

You'll need to specify at least `QUORUM` recovery files for the restoration to succeed.

## Implementation Details

People who are not cryptographers should never roll their own cryptography. I am not a cryptographer, so I've tried to make the most sensible choices in the implementation of The Last Resort using existing cryptographic implementations.

The Last Resort encrypts the plaintext using AES-256 in OCB mode. The entire cipher text is placed in every recovery file.

The AES key is generated by XOR-ing:

1. a key derived from the user-inputted password using PBKDF2 with SHA3-256
2. a random 32-byte key called the *pad*

The password-derived key is not stored. The pad is distributed among the recovery files: For each combination of `QUORUM` files among  `TOTAL`, we generate a *sequence* of 32-byte *pad fragments* such that XOR-ing all of the pad fragments in the sequence equals the pad. We place one pad fragment in each of the files in this particular combination. This ensures that any combination of `QUORUM` recovery files is guaranteed to contain the pad fragments of exactly one sequence in common. With a full sequence, we can reconstruct the pad. Combined with the password and number of PBKDF2 iterations, we can determine the full AES key and decrypt the ciphertext.

## License

```
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
```

## Further Reading

[*Before You Turn On Two Factor Authentication…*](https://medium.com/@stuartschechter/before-you-turn-on-two-factor-authentication-27148cc5b9a1) by Stuart Schechter
