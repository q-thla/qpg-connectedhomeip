# Matter QPG6105 Lock Example Application

An example application showing the use of
[Matter](https://github.com/project-chip/connectedhomeip) on the Qorvo QPG6105.

---

- [Matter QPG6105 Lock Example Application](#matter-qpg6105-lock-example-application)
  - [Lock-app](#lock-app)
    - [Build and program](#build-and-program)
    - [Button control](#button-control)
    - [LED output](#led-output)
    - [Logging Output](#logging-output)
  - [Additional resources](#additional-resources)

---

## Lock-app

The QPG6105 Lock-app shows an implementation of a Lock device, based on
Matter and the Qorvo QPG6105 SDK. Intention of this example is to demonstrate a Matter
device, with Thread connectivity, using Bluetooth Low Energy to perform Matter provisioning.

### Build and program

Building and programming instruction can be found on the platform specific page for

- [QPG6105](../../qpg6105/doc/README.md)

### Button control

This application uses following buttons of the DK board:

- `SW2`: Used to perform a HW reset for the full board
- `SW4`: Used to toggle the Unlock/Lock the simulated lock
- `SW5`: Used to perform, depending on the time the button is kept pressed,
  - Start Bluetooth LE advertising (released before 3s)
  - Trigger Thread joining (release after 3s)
  - Factory reset (released after 6s)

The button `SW1` and the slider switch `SW3` are unused.

### LED output

The following LEDs are used during the application:

- `LD1` - RED led: Status LED simulating the lock state
  - On - lock closed
  - Off - lock open
  - Blinking - lock moving to new state
- `LD2` - GRN led:
  - Short blink every 1s: Bluetooth LE advertising
  - Fast blinks: Bluetooth LE connected and subscribed
  - Short off: Thread connected
  - On: Full service connectivity

### Logging Output

See [View Logging Output](../../qpg6105/doc/README.md#view-logging-output)

At startup you will see:

    qvCHIP v0.0.0.0 (CL:155586) running
    [P][-] Init CHIP Stack
    [P][DL] BLEManagerImpl::Init() complete
    [P][-] Starting Platform Manager Event Loop
    [P][-] ============================
    [P][-] Qorvo Lock-app Launching
    [P][-] ============================
    [D][DL] CHIP task running

**Note:** Logging is currently encapsulated by the Qorvo logging module.
Output will have additional header and footer bytes.
This will be updated later into a raw stream for any serial terminal to parse.

## Additional resources

Please visit [www.qorvo.com](https://www.qorvo.com) for more information on our product line or contact us at <LPW.support@qorvo.com>.
