"""
Test script to verify cure probability distribution
Run multiple simulated cures to check if the 37% success rate for intensity=9 is realistic
"""
import random

def test_cure_probability(intensity, num_trials=1000):
    """Test cure success rate for given intensity"""
    cure_success_rate = max(30, min(95, 100 - (intensity * 7)))
    
    successes = 0
    for _ in range(num_trials):
        if random.random() * 100 < cure_success_rate:
            successes += 1
    
    actual_success_rate = (successes / num_trials) * 100
    
    print(f"Intensity {intensity}:")
    print(f"  Expected success rate: {cure_success_rate}%")
    print(f"  Actual success rate (n={num_trials}): {actual_success_rate:.1f}%")
    print(f"  Successes: {successes}/{num_trials}")
    print(f"  Average attempts needed: {num_trials/successes:.2f}")
    print()
    
    return actual_success_rate

if __name__ == "__main__":
    print("=" * 60)
    print("CURE PROBABILITY VERIFICATION")
    print("=" * 60)
    print()
    
    # Test different intensity levels
    intensities = [1, 3, 5, 7, 9, 10]
    
    for intensity in intensities:
        test_cure_probability(intensity, num_trials=1000)
    
    print("=" * 60)
    print("DETAILED ANALYSIS FOR INTENSITY=9 (current malware)")
    print("=" * 60)
    print()
    
    # Run 10 simulated infection cycles for intensity=9
    intensity = 9
    cure_success_rate = 37  # From formula: 100 - (9 * 7) = 37
    
    print(f"Running 10 simulated infection cycles...")
    print(f"Each cycle tries cures until successful (success_rate={cure_success_rate}%)")
    print()
    
    total_attempts = 0
    for cycle in range(1, 11):
        attempts = 0
        while True:
            attempts += 1
            if random.random() * 100 < cure_success_rate:
                break
        total_attempts += attempts
        print(f"  Cycle {cycle}: Cured after {attempts} attempt{'s' if attempts > 1 else ''}")
    
    avg_attempts = total_attempts / 10
    print()
    print(f"Average attempts needed: {avg_attempts:.2f}")
    print(f"Expected average (1/0.37): {1/0.37:.2f}")
    print()
    
    # Show what happened in our actual test
    print("=" * 60)
    print("ACTUAL TEST RESULT")
    print("=" * 60)
    print(f"In the simulation, the cure succeeded on the FIRST attempt.")
    print(f"Probability of this happening: {cure_success_rate}%")
    print(f"This is expected to happen ~{cure_success_rate} times out of 100.")
    print(f"So yes, we got 'lucky' but it's within expected variance!")
