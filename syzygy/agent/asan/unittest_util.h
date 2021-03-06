// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
#define SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_piece.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/memory_notifier.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/memory_notifiers/null_memory_notifier.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/trace/agent_logger/agent_logger.h"
#include "syzygy/trace/agent_logger/agent_logger_rpc_impl.h"

namespace testing {

using agent::asan::AsanErrorInfo;
using agent::asan::memory_notifiers::NullMemoryNotifier;
using agent::asan::StackCaptureCache;

// The default name of the runtime library DLL.
extern const wchar_t kSyzyAsanRtlDll[];

// A unittest fixture that ensures that an Asan logger instance is up and
// running for the duration of the test. Output is captured to a file so that
// its contents can be read after the test if necessary.
class TestWithAsanLogger : public testing::Test {
 public:
  TestWithAsanLogger();

  // @name testing::Test overrides.
  // @{
  void SetUp() override;
  void TearDown() override;
  // @}

  // @name Accessors.
  // @{
  const std::wstring& instance_id() const { return instance_id_; }
  const base::FilePath& log_file_path() const { return log_file_path_; }
  const base::FilePath& temp_dir() const { return temp_dir_.path(); }
  // @}

  bool LogContains(const base::StringPiece& message);

  // Delete the temporary file used for the logging and its directory.
  void DeleteTempFileAndDirectory();

  // Starts the logger process.
  void StartLogger();

  // Stops the logger process.
  void StopLogger();

  // Reset the log contents.
  void ResetLog();

  // Appends @p instance to the RPC logger instance environment variable.
  void AppendToLoggerEnv(const std::string &instance);

 private:
  // The instance ID used by the running logger instance.
  std::wstring instance_id_;

  // The path to the log file where the the logger instance will write.
  base::FilePath log_file_path_;

  // Status of the logger process.
  bool logger_running_;

  // A temporary directory into which the log file will be written.
  base::ScopedTempDir temp_dir_;

  // The contents of the log. These are read by calling LogContains.
  bool log_contents_read_;
  std::string log_contents_;

  // Value of the logger instance environment variable before SetUp.
  std::string old_logger_env_;

  // Redirection files for the logger.
  base::ScopedFILE logger_stdin_file_;
  base::ScopedFILE logger_stdout_file_;
  base::ScopedFILE logger_stderr_file_;
};

// Shorthand for discussing all the asan runtime functions.
#define ASAN_RTL_FUNCTIONS(F)  \
    F(WINAPI, HANDLE, GetProcessHeap, (), ())  \
    F(WINAPI, HANDLE, HeapCreate,  \
      (DWORD options, SIZE_T initial_size, SIZE_T maximum_size),  \
      (options, initial_size, maximum_size))  \
    F(WINAPI, BOOL, HeapDestroy,  \
      (HANDLE heap), (heap))  \
    F(WINAPI, LPVOID, HeapAlloc,  \
      (HANDLE heap, DWORD flags, SIZE_T bytes), (heap, flags, bytes))  \
    F(WINAPI, LPVOID, HeapReAlloc,  \
      (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T bytes),  \
      (heap, flags, mem, bytes))  \
    F(WINAPI, BOOL, HeapFree,  \
      (HANDLE heap, DWORD flags, LPVOID mem), (heap, flags, mem))  \
    F(WINAPI, SIZE_T, HeapSize,  \
      (HANDLE heap, DWORD flags, LPCVOID mem), (heap, flags, mem))  \
    F(WINAPI, BOOL, HeapValidate,  \
      (HANDLE heap, DWORD flags, LPCVOID mem), (heap, flags, mem))  \
    F(WINAPI, SIZE_T, HeapCompact,  \
      (HANDLE heap, DWORD flags), (heap, flags))  \
    F(WINAPI, BOOL, HeapLock, (HANDLE heap), (heap))  \
    F(WINAPI, BOOL, HeapUnlock, (HANDLE heap), (heap))  \
    F(WINAPI, BOOL, HeapWalk,  \
      (HANDLE heap, LPPROCESS_HEAP_ENTRY entry), (heap, entry))  \
    F(WINAPI, BOOL, HeapSetInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length),  \
      (heap, info_class, info, info_length))  \
    F(WINAPI, BOOL, HeapQueryInformation,  \
      (HANDLE heap, HEAP_INFORMATION_CLASS info_class,  \
       PVOID info, SIZE_T info_length, PSIZE_T return_length),  \
      (heap, info_class, info, info_length, return_length))  \
    F(WINAPI, void, SetCallBack,  \
      (void (*callback)(AsanErrorInfo* error_info)),  \
      (callback))  \
    F(_cdecl, void*, memcpy,  \
      (void* destination, const void* source,  size_t num),  \
      (destination, source, num))  \
    F(_cdecl, void*, memmove,  \
      (void* destination, const void* source, size_t num),  \
      (destination, source, num))  \
    F(_cdecl, void*, memset, (void* ptr, int value, size_t num),  \
      (ptr, value, num))  \
    F(_cdecl, const void*, memchr, (const void* ptr, int value, size_t num),  \
      (ptr, value, num))  \
    F(_cdecl, size_t, strcspn, (const char* str1, const char* str2),  \
      (str1, str2))  \
    F(_cdecl, size_t, strlen, (const char* str), (str))  \
    F(_cdecl, const char*, strrchr, (const char* str, int character),  \
      (str, character))  \
    F(_cdecl, const wchar_t*, wcsrchr, (const wchar_t* str, int character),  \
      (str, character))  \
    F(_cdecl, const wchar_t*, wcschr, (const wchar_t* str, int character),  \
      (str, character))  \
    F(_cdecl, int, strcmp, (const char* str1, const char* str2),  \
      (str1, str2))  \
    F(_cdecl, const char*, strpbrk, (const char* str1, const char* str2),  \
      (str1, str2))  \
    F(_cdecl, const char*, strstr, (const char* str1, const char* str2),  \
      (str1, str2))  \
    F(_cdecl, const wchar_t*, wcsstr, (const wchar_t* str1,  \
      const wchar_t* str2), (str1, str2))  \
    F(_cdecl, size_t, strspn, (const char* str1, const char* str2),  \
      (str1, str2))  \
    F(_cdecl, char*, strncpy,  \
      (char* destination, const char* source, size_t num),  \
      (destination, source, num))  \
    F(_cdecl, char*, strncat,  \
      (char* destination, const char* source, size_t num),  \
      (destination, source, num))  \
    F(WINAPI, BOOL, ReadFile,  \
      (HANDLE file_handle, LPVOID buffer, DWORD bytes_to_read,  \
       LPDWORD bytes_read, LPOVERLAPPED overlapped),  \
      (file_handle, buffer, bytes_to_read, bytes_read, overlapped))  \
    F(WINAPI, BOOL, WriteFile,  \
      (HANDLE file_handle, LPCVOID buffer, DWORD bytes_to_write,  \
       LPDWORD bytes_written, LPOVERLAPPED overlapped),  \
      (file_handle, buffer, bytes_to_write, bytes_written, overlapped))  \
    F(_cdecl, void, SetInterceptorCallback, (void (*callback)()), (callback))  \
    F(WINAPI, agent::asan::AsanRuntime*, GetActiveRuntime, (), ())  \
    F(WINAPI, void, SetAllocationFilterFlag, (), ())  \
    F(WINAPI, void, ClearAllocationFilterFlag, (), ())

// Declare pointer types for the intercepted functions.
#define DECLARE_ASAN_FUNCTION_PTR(convention, ret, name, args, argnames) \
  typedef ret (convention* name##FunctionPtr)args;
ASAN_RTL_FUNCTIONS(DECLARE_ASAN_FUNCTION_PTR)
#undef DECLARE_ASAN_FUNCTION_PTR

class TestAsanRtl : public testing::TestWithAsanLogger {
 public:
  TestAsanRtl() : asan_rtl_(NULL), heap_(NULL) {
  }

  void SetUp() override {
    testing::TestWithAsanLogger::SetUp();

    // Load the Asan runtime library.
    base::FilePath asan_rtl_path =
        testing::GetExeRelativePath(L"syzyasan_rtl.dll");
    asan_rtl_ = ::LoadLibrary(asan_rtl_path.value().c_str());
    ASSERT_TRUE(asan_rtl_ != NULL);

    // Load all the functions and assert that we find them.
#define LOAD_ASAN_FUNCTION(convention, ret, name, args, argnames)  \
    name##Function = reinterpret_cast<name##FunctionPtr>(  \
        ::GetProcAddress(asan_rtl_, "asan_" #name));  \
    ASSERT_TRUE(name##Function != NULL);

    ASAN_RTL_FUNCTIONS(LOAD_ASAN_FUNCTION)

#undef LOAD_ASAN_FUNCTION

    heap_ = HeapCreateFunction(0, 0, 0);
    ASSERT_TRUE(heap_ != NULL);

    agent::asan::AsanRuntime* runtime = GetActiveRuntimeFunction();
    ASSERT_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime);
    // Disable the heap checking as this really slows down the unittests.
    runtime->params().check_heap_on_failure = false;
  }

  void TearDown() override {
    if (heap_ != NULL) {
      HeapDestroyFunction(heap_);
      heap_ = NULL;
    }

    if (asan_rtl_ != NULL) {
      ::FreeLibrary(asan_rtl_);
      asan_rtl_ = NULL;
    }

    testing::TestWithAsanLogger::TearDown();
  }

  HANDLE heap() { return heap_; }

  // Declare pointers to intercepted functions.
#define DECLARE_FUNCTION_PTR_VARIABLE(convention, ret, name, args, argnames)  \
    static name##FunctionPtr name##Function;
  ASAN_RTL_FUNCTIONS(DECLARE_FUNCTION_PTR_VARIABLE)
#undef DECLARE_FUNCTION_PTR_VARIABLE

  // Define versions of all of the functions that expect an error to be thrown
  // by the AsanErrorCallback, and in turn raise an exception if the underlying
  // function didn't fail.
#define DECLARE_FAILING_FUNCTION(convention, ret, name, args, argnames)  \
    static void name##FunctionFailing args;
  ASAN_RTL_FUNCTIONS(DECLARE_FAILING_FUNCTION)
#undef DECLARE_FAILING_FUNCTION

 protected:
  // The AsanAsan runtime module to test.
  HMODULE asan_rtl_;

  // Scratch heap handle valid from SetUp to TearDown.
  HANDLE heap_;
};

// A helper struct to be passed as a destructor of Asan scoped allocation.
struct AsanDeleteHelper {
  explicit AsanDeleteHelper(TestAsanRtl* asan_rtl)
      : asan_rtl_(asan_rtl) {
  }

  void operator()(void* ptr) {
    asan_rtl_->HeapFreeFunction(asan_rtl_->heap(), 0, ptr);
  }
  TestAsanRtl* asan_rtl_;
};

// A scoped_ptr specialization for the Asan allocations.
template <typename T>
class ScopedAsanAlloc : public scoped_ptr<T, AsanDeleteHelper> {
 public:
  explicit ScopedAsanAlloc(TestAsanRtl* asan_rtl)
      : scoped_ptr(NULL, AsanDeleteHelper(asan_rtl)) {
  }

  ScopedAsanAlloc(TestAsanRtl* asan_rtl, size_t size)
      : scoped_ptr(NULL, AsanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
  }

  ScopedAsanAlloc(TestAsanRtl* asan_rtl, size_t size, const T* value)
      : scoped_ptr(NULL, AsanDeleteHelper(asan_rtl)) {
    Allocate(asan_rtl, size);
    ::memcpy(get(), value, size * sizeof(T));
  }

  template <typename T2>
  T2* GetAs() {
    return reinterpret_cast<T2*>(get());
  }

  void Allocate(TestAsanRtl* asan_rtl, size_t size) {
    ASSERT_TRUE(asan_rtl != NULL);
    reset(reinterpret_cast<T*>(
        asan_rtl->HeapAllocFunction(asan_rtl->heap(), 0, size * sizeof(T))));
    ::memset(get(), 0, size * sizeof(T));
  }

  T operator[](int i) const {
    CHECK(get() != NULL);
    return get()[i];
  }

  T& operator[](int i) {
    CHECK(get() != NULL);
    return get()[i];
  }
};

// A unittest fixture that initializes an Asan runtime instance.
class TestWithAsanRuntime : public testing::Test {
 public:
  TestWithAsanRuntime() {
    runtime_ = new agent::asan::AsanRuntime();
    owns_runtime_ = true;
  }

  explicit TestWithAsanRuntime(agent::asan::AsanRuntime* runtime)
      : runtime_(runtime), owns_runtime_(false) {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
  }

  ~TestWithAsanRuntime() {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    if (owns_runtime_)
      delete runtime_;
    runtime_ = NULL;
  }

  virtual void SetUp() override {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    testing::Test::SetUp();
    runtime_->SetUp(L"");
  }

  virtual void TearDown() override {
    CHECK_NE(reinterpret_cast<agent::asan::AsanRuntime*>(NULL), runtime_);
    runtime_->TearDown();
    testing::Test::TearDown();
  }

 protected:
  // The runtime instance used by the tests.
  agent::asan::AsanRuntime* runtime_;

  // Indicates if we own the runtime instance.
  bool owns_runtime_;
};

// A unittest fixture to test the bookkeeping functions.
struct FakeAsanBlock {
  static const size_t kMaxAlignmentLog = 13;
  static const size_t kMaxAlignment = 1 << kMaxAlignmentLog;
  // If we want to test the alignments up to 4096 we need a buffer of at least
  // 3 * 4096 bytes:
  // +--- 0 <= size < 4096 bytes---+---4096 bytes---+--4096 bytes--+
  // ^buffer                       ^aligned_buffer  ^user_pointer
  static const size_t kBufferSize = 3 * kMaxAlignment;
  static const uint8 kBufferHeaderValue = 0xAE;
  static const uint8 kBufferTrailerValue = 0xEA;

  FakeAsanBlock(size_t alloc_alignment_log, StackCaptureCache* stack_cache);

  ~FakeAsanBlock();

  // Initialize an Asan block in the buffer.
  // @param alloc_size The user size of the Asan block.
  // @returns true on success, false otherwise.
  bool InitializeBlock(size_t alloc_size);

  // Ensures that this block has a valid block header.
  bool TestBlockMetadata();

  // Mark the current Asan block as quarantined.
  bool MarkBlockAsQuarantined();

  // The buffer we use internally.
  uint8 buffer[kBufferSize];

  // The information about the block once it has been initialized.
  agent::asan::BlockInfo block_info;

  // The alignment of the current allocation.
  size_t alloc_alignment;
  size_t alloc_alignment_log;

  // The sizes of the different sub-structures in the buffer.
  size_t buffer_header_size;
  size_t buffer_trailer_size;

  // The pointers to the different sub-structures in the buffer.
  uint8* buffer_align_begin;

  // Indicate if the buffer has been initialized.
  bool is_initialized;

  // The cache that will store the stack traces of this block.
  StackCaptureCache* stack_cache;
};

// A mock memory notifier. Useful when testing objects that have a memory
// notifier dependency.
class MockMemoryNotifier : public agent::asan::MemoryNotifierInterface {
 public:
  // Constructor.
  MockMemoryNotifier() { }

  // Virtual destructor.
  virtual ~MockMemoryNotifier() { }

  // @name MemoryNotifierInterface implementation.
  // @{
  MOCK_METHOD2(NotifyInternalUse, void(const void*, size_t));
  MOCK_METHOD2(NotifyFutureHeapUse, void(const void*, size_t));
  MOCK_METHOD2(NotifyReturnedToOS, void(const void*, size_t));
  // @}

 private:
  DISALLOW_COPY_AND_ASSIGN(MockMemoryNotifier);
};

// A mock HeapInterface.
class LenientMockHeap : public agent::asan::HeapInterface {
 public:
  LenientMockHeap() { }
  virtual ~LenientMockHeap() { }
  MOCK_CONST_METHOD0(GetHeapType, agent::asan::HeapType());
  MOCK_CONST_METHOD0(GetHeapFeatures, uint32());
  MOCK_METHOD1(Allocate, void*(size_t));
  MOCK_METHOD1(Free, bool(void*));
  MOCK_METHOD1(IsAllocated, bool(const void*));
  MOCK_METHOD1(GetAllocationSize, size_t(const void*));
  MOCK_METHOD0(Lock, void());
  MOCK_METHOD0(Unlock, void());
  MOCK_METHOD0(TryLock, bool());
};
typedef testing::StrictMock<LenientMockHeap> MockHeap;

typedef std::vector<agent::asan::AsanBlockInfo> AsanBlockInfoVector;
typedef std::pair<agent::asan::AsanCorruptBlockRange, AsanBlockInfoVector>
    CorruptRangeInfo;
typedef std::vector<CorruptRangeInfo> CorruptRangeVector;

// A helper for testing SyzyAsan memory accessor instrumentation functions.
class MemoryAccessorTester {
 public:
  typedef agent::asan::BadAccessKind BadAccessKind;

  enum IgnoreFlags {
    IGNORE_FLAGS
  };
  MemoryAccessorTester();
  explicit MemoryAccessorTester(IgnoreFlags ignore_flags);
  ~MemoryAccessorTester();

  // Checks that @p access_fn doesn't raise exceptions on access checking
  // @p ptr, and that @p access_fn doesn't modify any registers or flags
  // when executed.
  void CheckAccessAndCompareContexts(FARPROC access_fn, void* ptr);

  // Checks that @p access_fn generates @p bad_access_type on checking @p ptr.
  void AssertMemoryErrorIsDetected(
      FARPROC access_fn, void* ptr, BadAccessKind bad_access_type);

  enum StringOperationDirection {
    DIRECTION_FORWARD,
    DIRECTION_BACKWARD
  };
  // Checks that @p access_fn doesn't raise exceptions on access checking
  // for a given @p direction, @p src, @p dst and @p len.
  void CheckSpecialAccessAndCompareContexts(
      FARPROC access_fn, StringOperationDirection direction,
      void* dst, void* src, int len);

  // Checks that @p access_fn generates @p bad_access_type on access checking
  // for a given @p direction, @p src, @p dst and @p len.
  void ExpectSpecialMemoryErrorIsDetected(
      FARPROC access_fn, StringOperationDirection direction,
      bool expect_error, void* dst, void* src, int32 length,
      BadAccessKind bad_access_type);

  static void AsanErrorCallback(AsanErrorInfo* error_info);

  void set_expected_error_type(BadAccessKind expected) {
    expected_error_type_ = expected;
  }
  bool memory_error_detected() const { return memory_error_detected_; }
  void set_memory_error_detected(bool memory_error_detected) {
    memory_error_detected_ = memory_error_detected;
  }

  const AsanErrorInfo& last_error_info() const { return last_error_info_; }
  const CorruptRangeVector& last_corrupt_ranges() const {
    return last_corrupt_ranges_;
  }

 private:
  void Initialize();
  void AsanErrorCallbackImpl(AsanErrorInfo* error_info);

  // This will be used in the asan callback to ensure that we detect the right
  // error.
  BadAccessKind expected_error_type_;
  // A flag used in asan callback to ensure that a memory error has been
  // detected.
  bool memory_error_detected_;

  // Indicates whether to ignore changes to the flags register.
  bool ignore_flags_;

  // The pre- and post-invocation contexts.
  CONTEXT context_before_hook_;
  CONTEXT context_after_hook_;
  // Context captured on error.
  CONTEXT error_context_;

  // The information about the last error.
  AsanErrorInfo last_error_info_;
  CorruptRangeVector last_corrupt_ranges_;

  // There shall be only one!
  static MemoryAccessorTester* instance_;
};

// A fixture class for testing memory interceptors.
class TestMemoryInterceptors : public TestWithAsanLogger {
 public:
  // Redefine some enums for local use.
  enum AccessMode {
    AsanReadAccess = agent::asan::ASAN_READ_ACCESS,
    AsanWriteAccess = agent::asan::ASAN_WRITE_ACCESS,
    AsanUnknownAccess = agent::asan::ASAN_UNKNOWN_ACCESS,
  };

  struct InterceptFunction {
    void(*function)();
    size_t size;
  };

  struct StringInterceptFunction {
    void(*function)();
    size_t size;
    AccessMode dst_access_mode;
    AccessMode src_access_mode;
    bool uses_counter;
  };

  static const bool kCounterInit_ecx = true;
  static const bool kCounterInit_1 = false;

  TestMemoryInterceptors();
  void SetUp() override;
  void TearDown() override;

  template <size_t N>
  void TestValidAccess(const InterceptFunction (&fns)[N]) {
    TestValidAccess(fns, N);
  }
  template <size_t N>
  void TestValidAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestValidAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestOverrunAccess(const InterceptFunction (&fns)[N]) {
    TestOverrunAccess(fns, N);
  }
  template <size_t N>
  void TestOverrunAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestOverrunAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestUnderrunAccess(const InterceptFunction (&fns)[N]) {
    TestUnderrunAccess(fns, N);
  }
  template <size_t N>
  void TestUnderrunAccessIgnoreFlags(const InterceptFunction (&fns)[N]) {
    TestUnderrunAccessIgnoreFlags(fns, N);
  }
  template <size_t N>
  void TestStringValidAccess(const StringInterceptFunction (&fns)[N]) {
    TestStringValidAccess(fns, N);
  }
  template <size_t N>
  void TestStringOverrunAccess(const StringInterceptFunction (&fns)[N]) {
    TestStringOverrunAccess(fns, N);
  }

 protected:
  void TestValidAccess(const InterceptFunction* fns, size_t num_fns);
  void TestValidAccessIgnoreFlags(const InterceptFunction* fns,
                                  size_t num_fns);
  void TestOverrunAccess(const InterceptFunction* fns, size_t num_fns);
  void TestOverrunAccessIgnoreFlags(const InterceptFunction* fns,
                                    size_t num_fns);
  void TestUnderrunAccess(const InterceptFunction* fns, size_t num_fns);
  void TestUnderrunAccessIgnoreFlags(const InterceptFunction* fns,
                                     size_t num_fns);
  void TestStringValidAccess(
      const StringInterceptFunction* fns, size_t num_fns);
  void TestStringOverrunAccess(
      const StringInterceptFunction* fns, size_t num_fns);

  const size_t kAllocSize = 64;

  agent::asan::AsanRuntime asan_runtime_;
  HANDLE heap_;

  // Convenience allocs of kAllocSize. Valid from SetUp to TearDown.
  byte* src_;
  byte* dst_;
};

// A very lightweight dummy heap to be used in stress testing the
// HeapAllocator. Lock and Unlock are noops, so this is not thread
// safe.
class DummyHeap : public agent::asan::HeapInterface {
 public:
  virtual ~DummyHeap() { }
  virtual agent::asan::HeapType GetHeapType() const {
    return agent::asan::kUnknownHeapType;
  }
  virtual uint32 GetHeapFeatures() const { return 0; }
  virtual void* Allocate(size_t bytes) { return ::malloc(bytes); }
  virtual bool Free(void* alloc) { ::free(alloc); return true; }
  virtual bool IsAllocated(const void* alloc) { return false; }
  virtual size_t GetAllocationSize(const void* alloc) { return 0; }
  virtual void Lock() { return; }
  virtual void Unlock() { return; }
  virtual bool TryLock() { return true; }
};

// Test read and write access.
// Use carefully, since it will try to overwrite the value at @p address with 0.
// @returns true if the address is readable and writable, false otherwise.
bool IsAccessible(void* address);

// Test read and write access.
// Use carefully, since it will try to overwrite the value at @p address with 0.
// @returns true if the address is neither readable nor writable,
//     false otherwise.
bool IsNotAccessible(void* address);

}  // namespace testing

#endif  // SYZYGY_AGENT_ASAN_UNITTEST_UTIL_H_
