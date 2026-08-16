//
// SPDX-FileCopyrightText: 2026 coolishsec0175
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

void spoof_lock_state(void) {
    uint32_t addr = 0;

    // Apply the seccfg_get_lock_state patch only when spoofing is enabled.
    // is_spoofing_enabled() reads the KAERU_ENV_BLDR_SPOOF env var via
    // get_env(), which is safe here because we are hooked at env_init_done.
    if (!is_spoofing_enabled()) {
        printf("spoof disabled\n");
        return;
    }
    printf("spoof enabled, applying seccfg patch\n");
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
}

void board_early_init(void) {
    printf("Entering early init for Infinix Note 30 5G\n");

    uint32_t addr = 0;

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

    // When the device reports as locked, AVB verifies vbmeta public
    // keys in two places inside load_and_verify_vbmeta: once for the
    // main vbmeta image and once for chained vbmeta images. Both reject
    // the boot if the key doesn't match, causing the "Public key used to
    // sign data rejected" error and a boot loop. Patch both checks so
    // any key is accepted regardless, as the LXX503 reference does.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF47F, 0xAE71, 0xE68D, 0xF8DD);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // The chain key check first compares key lengths before calling
        // memcmp. If lengths differ, it skips memcmp and falls straight
        // to the error path. Change "cmp r2, r3" to "cmp r3, r3" so the
        // length check always succeeds, allowing execution to reach the
        // memcmp path (which we NOP below).
        PATCH_MEM(addr - 0x320, 0x451B);

        // NOP the bne.w that rejects mismatched chained vbmeta keys,
        // falling through to the success path unconditionally.
        NOP(addr, 2);

        // Replace "cmp r3, #0" with "movs r3, #1" so key_is_trusted
        // is always nonzero and the following bne.w takes the success
        // branch.
        PATCH_MEM(addr + 0x70, 0x2301);
    }

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 1);

    // Hook into env_init_done after environment initialization so
    // is_spoofing_enabled() (via get_env) is safe to call.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF03A, 0xF9CC, 0x6823, 0x2000);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void *)spoof_lock_state, TARGET_THUMB);
    }
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