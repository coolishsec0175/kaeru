//
// SPDX-FileCopyrightText: 2026 coolishsec0175
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

#define VOLUME_DOWN 17
#define VOLUME_UP 18

#define KAERU_BANNER "kaeru for Infinix Note 30 5G (X6711)"

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // Make seccfg_get_lock_state always report lock_state=1 and return 2,
    // so the TEE and system see the bootloader as "locked".
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB1D0, 0xB510, 0x4604, 0xF7FF, 0xFFDD);
    if (addr) {
        printf("Found seccfg_get_lock_state at 0x%08X\n", addr);
        PATCH_MEM(addr + 6,
            0x2301,  // movs r3, #1
            0x6023,  // str r3, [r4, #0]
            0x2002,  // movs r0, #2
            0xBD10   // pop {r4, pc}
        );
    }

    // Force the secure boot state to ATTR_SBOOT_ENABLE (0x11).
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0x4604, 0x2001, 0xF7FF);
    if (addr) {
        printf("Found get_sboot_state at 0x%08X\n", addr);
        PATCH_MEM(addr,
            0x2311,  // movs r3, #0x11
            0x6003,  // str r3, [r0, #0]
            0x2000,  // movs r0, #0
            0x4770   // bx lr
        );
    }
}

static void cmd_banner(const char* arg, void* data, unsigned sz) {
    fastboot_info(KAERU_BANNER);
    fastboot_info("Custom commands:");
    fastboot_info("  oem banner            - show this info");
    fastboot_info("  oem getmode           - show current boot mode");
    fastboot_info("  oem keytest           - report held volume key");
    fastboot_info("  oem bootmode <mode>   - set boot mode for next boot");
    fastboot_okay("");
}

static void cmd_getmode(const char* arg, void* data, unsigned sz) {
    char msg[64];
    npf_snprintf(msg, sizeof(msg), "bootmode=%s (%d)",
                 bootmode2str(get_bootmode()), get_bootmode());
    fastboot_info(msg);
    fastboot_okay("");
}

static void cmd_keytest(const char* arg, void* data, unsigned sz) {
    if (mtk_detect_key(VOLUME_DOWN)) {
        fastboot_info("volume_down=held");
        fastboot_okay("");
        return;
    }

    if (mtk_detect_key(VOLUME_UP)) {
        fastboot_info("volume_up=held");
        fastboot_okay("");
        return;
    }

    fastboot_info("volume_down=released");
    fastboot_info("volume_up=released");
    fastboot_okay("");
}

static int bootmode_by_name(const char* name, bootmode_t* mode) {
    static const struct {
        const char* name;
        bootmode_t mode;
    } modes[] = {
        { "normal", BOOTMODE_NORMAL },
        { "meta", BOOTMODE_META },
        { "recovery", BOOTMODE_RECOVERY },
        { "factory", BOOTMODE_FACTORY },
        { "advmeta", BOOTMODE_ADVMETA },
        { "atefact", BOOTMODE_ATEFACT },
        { "alarm", BOOTMODE_ALARM },
        { "poweroff-charging", BOOTMODE_POWEROFF_CHARGING },
        { "fastboot", BOOTMODE_FASTBOOT },
        { "erecovery", BOOTMODE_ERECOVERY },
        { "laf", BOOTMODE_LAF },
    };

    for (size_t i = 0; i < ARRAY_SIZE(modes); i++) {
        if (streq(name, modes[i].name)) {
            *mode = modes[i].mode;
            return 0;
        }
    }

    return -1;
}

static void cmd_bootmode(const char* arg, void* data, unsigned sz) {
    while (*arg == ' ') arg++;

    bootmode_t mode;
    char msg[64];

    if (bootmode_by_name(arg, &mode) == 0) {
        set_bootmode(mode);
        npf_snprintf(msg, sizeof(msg), "bootmode set to %s (%d)",
                     bootmode2str(mode), mode);
        fastboot_info(msg);
        fastboot_info("Reboot for it to take effect.");
        fastboot_okay("");
        return;
    }

    if (ISDIGIT(*arg)) {
        const char* p = arg;
        unsigned long val = 0;
        while (ISDIGIT(*p)) {
            val = val * 10 + (unsigned long)(*p - '0');
            p++;
        }
        if (*p == '\0' || *p == ' ') {
            mode = (bootmode_t)val;
            set_bootmode(mode);
            npf_snprintf(msg, sizeof(msg), "bootmode set to %s (%d)",
                         bootmode2str(mode), mode);
            fastboot_info(msg);
            fastboot_info("Reboot for it to take effect.");
            fastboot_okay("");
            return;
        }
    }

    fastboot_info("Valid modes: normal meta recovery factory advmeta atefact");
    fastboot_info("             alarm poweroff-charging fastboot erecovery laf");
    fastboot_info("Or use a numeric value, e.g. 99 = fastboot, 2 = recovery");
    fastboot_fail("Usage: fastboot oem bootmode <mode>");
}

void board_early_init(void) {
    printf("Entering early init for Infinix Note 30 5G\n");

    fastboot_register("oem banner", cmd_banner, 1);
    fastboot_register("oem getmode", cmd_getmode, 1);
    fastboot_register("oem keytest", cmd_keytest, 1);
    fastboot_register("oem bootmode", cmd_bootmode, 1);
    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 1);
}

void board_late_init(void) {
    printf("Entering late init for Infinix Note 30 5G\n");

    uint32_t addr = 0;

    // Environment is initialized by the time we get here, so we can apply
    // the bootloader lock state spoofing patches directly.
    spoof_lock_state();

    // Patch to enable:
    // - Volume Down → Fastboot
    // - Volume Up → Recovery
    if (mtk_detect_key(VOLUME_DOWN)) {
        set_bootmode(BOOTMODE_FASTBOOT);
        show_bootmode(BOOTMODE_FASTBOOT);
    } else if (mtk_detect_key(VOLUME_UP)) {
        set_bootmode(BOOTMODE_RECOVERY);
        show_bootmode(BOOTMODE_RECOVERY);
    }

    // Suppresses the bootloader unlock warning shown during boot on
    // unlocked devices. In addition to the visual warning, it also
    // introduces an unnecessary 5-second delay.
    //
    // This patch get rid of the delay and the warning by forcing the
    // function that holds the logic to always return 0 and therefore
    // not executing the code that shows the warning.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B0E, 0x447B);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Disables the warning shown during boot when the device is unlocked and
    // the dm-verity state is corrupted. This behaves like the previous lock
    // state warnings, visual only, with no real impact.
    //
    // Same approach: patch the function to always return 0.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB530, 0xB083, 0xAB02, 0x2200);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
}
