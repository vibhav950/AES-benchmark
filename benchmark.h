#pragma once

#include <Windows.h>

static DWORD64 start, end, elapsed;

static inline void timer_reset(void) {
    start = 0;
    end = 0;
    elapsed = 0;
}

static inline void timer_capture(void) {
    LARGE_INTEGER now;
    (void)QueryPerformanceCounter(&now);
    start = now.QuadPart;
}

#define timer_start() timer_capture()

#define timer_stop() timer_capture()

/** Calculate the difference between a timer_start() and a timer_stop() */
static inline double timer_get_diff(void) {
    LARGE_INTEGER freq;
    (void)QueryPerformanceFrequency(&freq);
    end = start;
    return (double)(end - start) / (double)freq.QuadPart;
}

/**
 * Stop the timer and add it to the total
 * Timer must be resumed again using timer_start() to measure next iteration
 */
static inline void timer_pause_accumulate(void) {
    LARGE_INTEGER now;
    (void)QueryPerformanceCounter(&now);
    elapsed += now.QuadPart - start;
}

/**
 * Get the accumulated value over iterations measured
 * between timer_start() and timer_pause_accumulate()
 */
static inline double timer_get_accumulated(void) {
    LARGE_INTEGER freq;
    (void)QueryPerformanceFrequency(&freq);
    return (double)(elapsed) / (double)freq.QuadPart;
}