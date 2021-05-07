#include <android/log.h>
#include <jni.h>
#include <string>

#define LOG_TAG    "leak"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* alias;

static void foo3(const char** a) {
    LOGI("in foo3\n");
    *a = alias;
}

static void foo2(const char** a) {
    LOGI("in foo2\n");
    return foo3(a);
}

static void foo1(const char** a) {
    LOGI("in foo1\n");
    return foo2(a);
}

extern "C" JNIEXPORT void JNICALL
Java_com_borza_increasing_1calldepth_MainActivity_send(JNIEnv *env, jclass clazz, jstring data) {
    const char *bytes = env->GetStringUTFChars(data, 0);
    alias = bytes;

    const char* alias2;
    foo1(&alias2);
    LOGI("%s", alias2);
}
