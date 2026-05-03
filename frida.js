// frida -U -f <package> -l frida.js
// Offsets come from dump.dart (JSONL format): jq -r '.offset' dump.dart

function hookFunc() {
  var dumpOffset = "0x20801C"; // offset from dump.dart (relative to _kDartIsolateSnapshotInstructions)

  var argBufferSize = 150;

  // Get base address of libapp.so — works across Frida 15, 16, and 17
  var address;
  try {
    address = Module.findBaseAddress("libapp.so");        // Frida < 16
  } catch (_) { /* removed in newer Frida */ }

  if (!address) {
    try {
      address = Module.getBaseAddress("libapp.so");       // Frida >= 16
    } catch (_) { /* fall through */ }
  }

  if (!address) {
    var mod = Process.findModuleByName("libapp.so");      // universal fallback
    if (mod) address = mod.base;
  }

  if (!address) {
    console.log("ERROR: libapp.so not found in process memory");
    return;
  }
  console.log("\n\nbaseAddress: " + address.toString());

  var codeOffset = address.add(dumpOffset);
  console.log("codeOffset: " + codeOffset.toString());
  console.log("");
  console.log("Wait..... ");

  Interceptor.attach(codeOffset, {
    onEnter: function (args) {
      console.log("");
      console.log("--------------------------------------------|");
      console.log("\n    Hook Function: " + dumpOffset);
      console.log("");
      console.log("--------------------------------------------|");
      console.log("");

      for (var argStep = 0; argStep < 50; argStep++) {
        try {
          dumpArgs(argStep, args[argStep], argBufferSize);
        } catch (e) {
          break;
        }
      }
    },
    onLeave: function (retval) {
      console.log("RETURN : " + retval);
      dumpArgs(0, retval, 150);
    },
  });
}

function dumpArgs(step, address, bufSize) {
  var buf = Memory.readByteArray(address, bufSize);

  console.log(
    "Argument " +
      step +
      " address " +
      address.toString() +
      " " +
      "buffer: " +
      bufSize.toString() +
      "\n\n Value:\n" +
      hexdump(buf, {
        offset: 0,
        length: bufSize,
        header: false,
        ansi: false,
      }),
  );

  console.log("");
  console.log("----------------------------------------------------");
  console.log("");
}

setTimeout(hookFunc, 1000);
