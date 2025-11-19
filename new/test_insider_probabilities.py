"""
Test script to verify probabilistic behavior of insider threat system.
Tests detection evasion, lateral spread, infection success, and mitigation evasion.
"""

import random


def test_detection_evasion(num_trials=1000):
    """Test monitoring detection evasion probabilities."""
    print("=" * 70)
    print("TESTING DETECTION EVASION (monitoring.py)")
    print("=" * 70)

    # Test different intensities with varying reasons
    print("\nVarying Intensity (1 reason):")
    print("-" * 70)
    for intensity in [1, 2, 5, 7, 9, 11]:
        evaded_count = 0
        detected_count = 0
        num_reasons = 1

        for _ in range(num_trials):
            base_detection_rate = 60
            detection_bonus = num_reasons * 15
            intensity_penalty = intensity * 5
            detection_rate = min(95, max(20, base_detection_rate + detection_bonus - intensity_penalty))

            if random.randint(1, 100) > detection_rate:
                evaded_count += 1
            else:
                detected_count += 1

        evaded_pct = (evaded_count / num_trials) * 100
        detected_pct = (detected_count / num_trials) * 100
        expected_detection = min(95, max(20, 60 + num_reasons * 15 - intensity * 5))

        print(f"Intensity: {intensity:2d} | Expected Detection: {expected_detection:2d}%")
        print(f"  Detected: {detected_count}/{num_trials} ({detected_pct:.1f}%)")
        print(f"  Evaded:   {evaded_count}/{num_trials} ({evaded_pct:.1f}%)")

    # Test different numbers of suspicious reasons (intensity=5)
    print("\nVarying Reasons (intensity=5):")
    print("-" * 70)
    for num_reasons in [1, 2, 3, 4]:
        evaded_count = 0
        detected_count = 0
        intensity = 5

        for _ in range(num_trials):
            base_detection_rate = 60
            detection_bonus = num_reasons * 15
            intensity_penalty = intensity * 5
            detection_rate = min(95, max(20, base_detection_rate + detection_bonus - intensity_penalty))

            if random.randint(1, 100) > detection_rate:
                evaded_count += 1
            else:
                detected_count += 1

        evaded_pct = (evaded_count / num_trials) * 100
        detected_pct = (detected_count / num_trials) * 100
        expected_detection = min(95, max(20, 60 + num_reasons * 15 - intensity * 5))

        print(f"Reasons: {num_reasons} | Expected Detection: {expected_detection}%")
        print(f"  Detected: {detected_count}/{num_trials} ({detected_pct:.1f}%)")
        print(f"  Evaded:   {evaded_count}/{num_trials} ({evaded_pct:.1f}%)")


def test_lateral_spread(num_trials=1000):
    """Test lateral movement spread success probabilities."""
    print("\n" + "=" * 70)
    print("TESTING LATERAL SPREAD (node.py - LateralMovementBehaviour)")
    print("=" * 70)

    for intensity in [1, 2, 5, 7, 9, 10]:
        success_count = 0
        failed_count = 0

        for _ in range(num_trials):
            spread_success_rate = min(95, intensity * 10)

            if random.randint(1, 100) > spread_success_rate:
                failed_count += 1
            else:
                success_count += 1

        success_pct = (success_count / num_trials) * 100
        failed_pct = (failed_count / num_trials) * 100
        expected_success = min(95, intensity * 10)

        print(f"\nIntensity: {intensity} | Expected Success: {expected_success}%")
        print(f"  Spread Success: {success_count}/{num_trials} ({success_pct:.1f}%)")
        print(f"  Spread Failed:  {failed_count}/{num_trials} ({failed_pct:.1f}%)")


def test_infection_success(num_trials=1000):
    """Test lateral infection success probabilities."""
    print("\n" + "=" * 70)
    print("TESTING INFECTION SUCCESS (node.py - LATERAL_SPREAD handler)")
    print("=" * 70)

    for intensity in [1, 2, 5, 7, 9, 10, 11]:
        success_count = 0
        blocked_count = 0

        for _ in range(num_trials):
            infection_success_rate = min(90, 40 + (intensity * 5))

            if random.randint(1, 100) > infection_success_rate:
                blocked_count += 1
            else:
                success_count += 1

        success_pct = (success_count / num_trials) * 100
        blocked_pct = (blocked_count / num_trials) * 100
        expected_success = min(90, 40 + intensity * 5)

        print(f"\nIntensity: {intensity} | Expected Success: {expected_success}%")
        print(f"  Infection Success: {success_count}/{num_trials} ({success_pct:.1f}%)")
        print(f"  Infection Blocked: {blocked_count}/{num_trials} ({blocked_pct:.1f}%)")


def test_mitigation_evasion(num_trials=1000):
    """Test response mitigation evasion probabilities."""
    print("\n" + "=" * 70)
    print("TESTING MITIGATION EVASION (response.py - 1st offense)")
    print("=" * 70)

    for intensity in [1, 2, 5, 7, 9, 11]:
        evaded_count = 0
        mitigated_count = 0

        for _ in range(num_trials):
            mitigation_success_rate = max(40, 95 - (intensity * 5))

            if random.randint(1, 100) > mitigation_success_rate:
                evaded_count += 1
            else:
                mitigated_count += 1

        evaded_pct = (evaded_count / num_trials) * 100
        mitigated_pct = (mitigated_count / num_trials) * 100
        expected_success = max(40, 95 - intensity * 5)

        print(f"\nIntensity: {intensity} | Expected Mitigation: {expected_success}%")
        print(f"  Mitigated:     {mitigated_count}/{num_trials} ({mitigated_pct:.1f}%)")
        print(f"  Evaded (1st):  {evaded_count}/{num_trials} ({evaded_pct:.1f}%)")


def test_combined_scenario_single(intensity, num_trials=1000):
    """Test combined probability scenario for a single intensity level."""
    num_reasons = 1  # Keyword detection

    # Track outcomes
    full_success = 0  # Evaded detection, spread, infected, evaded mitigation
    detected_early = 0
    spread_failed = 0
    infection_blocked = 0
    mitigated = 0

    for _ in range(num_trials):
        # Step 1: Detection (with intensity penalty)
        base_detection_rate = 60
        detection_bonus = num_reasons * 15
        intensity_penalty = intensity * 5
        detection_rate = min(95, max(20, base_detection_rate + detection_bonus - intensity_penalty))

        if random.randint(1, 100) > detection_rate:
            # Evaded detection - can proceed
            pass
        else:
            detected_early += 1
            continue

        # Step 2: Lateral spread attempt
        spread_success_rate = min(95, intensity * 10)
        if random.randint(1, 100) > spread_success_rate:
            spread_failed += 1
            continue

        # Step 3: Infection success
        infection_success_rate = min(90, 40 + intensity * 5)
        if random.randint(1, 100) > infection_success_rate:
            infection_blocked += 1
            continue

        # Step 4: Mitigation (if eventually detected)
        # Assume later detection with more reasons (reduces intensity penalty)
        detection_rate_later = min(95, max(20, 60 + 2 * 15 - intensity * 5))  # 2 reasons
        if random.randint(1, 100) <= detection_rate_later:
            # Detected - attempt mitigation
            mitigation_success_rate = max(40, 95 - intensity * 5)
            if random.randint(1, 100) <= mitigation_success_rate:
                mitigated += 1
                continue

        # Made it through all defenses
        full_success += 1

    return {
        'intensity': intensity,
        'detected_early': detected_early,
        'spread_failed': spread_failed,
        'infection_blocked': infection_blocked,
        'mitigated': mitigated,
        'full_success': full_success,
        'total_stopped': detected_early + spread_failed + infection_blocked + mitigated
    }


def test_combined_scenario(num_trials=1000):
    """Test combined probability scenario: full attack chain for various intensities."""
    print("\n" + "=" * 70)
    print("TESTING COMBINED SCENARIO (Full Attack Chain)")
    print("=" * 70)
    print("Testing multiple intensity levels through all defense layers")
    print("-" * 70)

    intensities = [1, 2, 5, 7, 9, 11]
    results = []

    for intensity in intensities:
        result = test_combined_scenario_single(intensity, num_trials)
        results.append(result)

    # Print header
    print(
        f"\n{'Int':>3} | {'Detected':>8} | {'Spread':>8} | {'Infect':>8} | {'Mitig':>8} | {'Success':>8} | {'Stopped':>8}")
    print(f"{'':>3} | {'Early':>8} | {'Failed':>8} | {'Blocked':>8} | {'(later)':>8} | {'(Full)':>8} | {'Total':>8}")
    print("-" * 70)

    for r in results:
        intensity = r['intensity']
        detected = r['detected_early']
        spread_fail = r['spread_failed']
        infect_block = r['infection_blocked']
        mitigated = r['mitigated']
        success = r['full_success']
        stopped = r['total_stopped']

        print(f"{intensity:3d} | {detected:4d} {detected / num_trials * 100:3.0f}% | "
              f"{spread_fail:4d} {spread_fail / num_trials * 100:3.0f}% | "
              f"{infect_block:4d} {infect_block / num_trials * 100:3.0f}% | "
              f"{mitigated:4d} {mitigated / num_trials * 100:3.0f}% | "
              f"{success:4d} {success / num_trials * 100:3.0f}% | "
              f"{stopped:4d} {stopped / num_trials * 100:3.0f}%")

    print("\n" + "=" * 70)
    print("ANALYSIS:")
    print("-" * 70)

    for r in results:
        intensity = r['intensity']
        success_rate = r['full_success'] / num_trials * 100
        stopped_rate = r['total_stopped'] / num_trials * 100

        if intensity <= 2:
            skill_level = "Low-skill"
        elif intensity <= 5:
            skill_level = "Medium-skill"
        elif intensity <= 8:
            skill_level = "High-skill"
        else:
            skill_level = "Expert-level"

        print(
            f"Intensity {intensity:2d} ({skill_level:>13s}): {success_rate:4.1f}% full success, {stopped_rate:4.1f}% stopped")

    print("=" * 70)


if __name__ == "__main__":
    random.seed(42)  # For reproducibility

    print("\n" + "=" * 70)
    print("INSIDER THREAT PROBABILISTIC SYSTEM TEST")
    print("=" * 70)
    print("Testing with 1000 trials per scenario")
    print("=" * 70)

    test_detection_evasion()
    test_lateral_spread()
    test_infection_success()
    test_mitigation_evasion()
    test_combined_scenario()

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)