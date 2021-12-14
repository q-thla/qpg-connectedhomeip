# Matter QPG6105 Lighting Example Application

An example application showing the use of
[Matter](https://github.com/project-chip/connectedhomeip) on the Qorvo QPG6105.

---

- [Matter QPG6105 Lighting Example Application](#matter-qpg6105-lighting-example-application)
  - [Lighting-app](#lighting-app)
    - [Build and program](#build-and-program)
    - [Button control](#button-control)
    - [LED output](#led-output)
    - [Logging Output](#logging-output)
  - [Additional resources](#additional-resources)

---

## Lighting-app

The QPG6105 Lighting-app shows an implementation of a Lighting device, based on
Matter and the Qorvo QPG6105 SDK. Intention of this example is to demonstrate a Matter
device, with Thread connectivity, using Bluetooth Low Energy to perform Matter provisioning.

### Build and program

Building and programming instruction can be found on the platform specific page for

- [QPG6105](../../qpg6105/doc/README.md)

### Button control

This application uses following buttons of the DK board:

- `SW1`: Used to toggle the light between two levels
- `SW2`: Used to perform a HW reset for the full board
- `SW4`: Used to toggle the off/on state of the simulated light
- `SW5`: Used to perform, depending on the time the button is kept pressed,
  - Software update - not yet supported (released before 3s)
  - Trigger Thread joining (release after 3s)
  - Factory reset (released after 6s)

The slider switch `SW3` is unused.

### LED output

The following LEDs are used during the application:

- `LD2` - GRN led:
  - Short blink every 1s: Bluetooth LE advertising
  - Fast blinks: Bluetooth LE connected and subscribed
  - Short off: Thread connected
  - On: Full service connectivity
- `LD3` - WHT led:
  - Off: Light is off
  - Dim: Light is set to low level
  - Bright: Light is set to high level

### Logging Output

See [View Logging Output](../../qpg6105/doc/README.md#view-logging-output)

At startup you will see:

    qvCHIP v0.0.0.0 (CL:155586) running
    [P][-] Init CHIP Stack
    [P][DL] BLEManagerImpl::Init() complete
    [P][-] Starting Platform Manager Event Loop
    [P][-] ============================
    [P][-] Qorvo Lighting-app Launching
    [P][-] ============================
    [D][DL] CHIP task running

**Note:** Logging is currently encapsulated by the Qorvo logging module.
Output will have additional header and footer bytes.
This will be updated later into a raw stream for any serial terminal to parse.

## Additional resources

Please visit [www.qorvo.com](https://www.qorvo.com) for more information on our product line or contact us at <LPW.support@qorvo.com>.
