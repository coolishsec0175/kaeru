//
// SPDX-FileCopyrightText: 2026 coolishsec0175
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

void board_early_init(void) {
    printf("Entering early init for Infinix Note 30 5G\n");

    uint32_t addr = 0;

    // The environment area is not initialized yet when board_early_init
    // runs, so get_env() / fastboot_publish() are NOT safe to call here
    // (they crashed the boot with a black screen on this MT6833 image).
    // Following the X6739 reference, we apply every patch unconditionally
    // instead of gating it behind an env flag.

    // Make seccfg_get_lock_state always report lock_state=1 and return 2,
    // so the TEE and system see the bootloader as "locked".
    //
    // NOTE: get_sboot_state is intentionally NOT patched. The merlin
    // reference (same MT6833 SoC) does not patch it, and forcing
    // ATTR_SBOOT_ENABLE (0x11) here caused a black screen during boot.
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

    // Regardless of whether spoofing is enabled, we always need to
    // disable image authentication. The user may just be using this
    // custom LK to unlock their device, or they may be spoofing
    // where the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate
    // verification for all partitions and firmware images (boot,
    // recovery, dtbo, SCP, etc.) so the device can boot with
    // modified or unsigned images.
    addr = SEARCH_PATTERN(LK_START, LK_END,
                          0xB508, 0xF7FF, 0xFF5F, 0xF3C0, 0x0040, 0xBD08);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Since we're spoofing the LKS_STATE as locked, get_dl_policy would
    // normally restrict fastboot downloads/flashing based on security
    // policy. Force it to return 0 to bypass these restrictions and
    // allow unrestricted flashing.
    addr = SEARCH_PATTERN(LK_START, LK_END,
                          0xB508, 0xF7FF, 0xFF59, 0xF000, 0x0001, 0xBD08);
    if (addr) {
        printf("Found get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Since we report the device as locked, AVB treats a bad signature,
    // hash mismatch, rollback or rejected key as fatal and won't boot
    // modified or resigned images. Force it into "allow verification
    // error" mode, the same path AVB uses when unlocked, so it tolerates
    // any vbmeta and still builds slot_data and the kernel cmdline.
    //
    // This LK has a slightly different instruction ordering than the
    // reference (str r3,[sp,#0x34] comes before eor sl,r3,#1), so we
    // use the ordering present in this image.
    addr = SEARCH_PATTERN(LK_START, LK_END,
                          0xF005, 0x0301, 0x930D, 0xF083, 0x0A01, 0x9B70);
    if (addr) {
        printf("Found avb_slot_verify allow-error gate at 0x%08X\n", addr);
        // and r3, r5, #1  ->  mov.w r3, #1
        PATCH_MEM(addr, 0xF04F, 0x0301);
    }

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 1);
}

void board_late_init(void) {
    printf("Entering late init for Infinix Note 30 5G\n");

    uint32_t addr = 0;

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