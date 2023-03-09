#include "commands.pb.h"
#include "fuse.h"
#include <sys/stat.h>
#include <fstream>
#include "src/libfuzzer/libfuzzer_macro.h"

extern struct fuse_operations ops;

extern "C" void SetupFs();
extern "C" void TeardownFs();

#define MAX_BUFFER_SIZE (4096*1000)

std::string GetPath(const Path& path) {
  if(path.components().empty()) {
    return "/";
  }
  std::string path_str{};
  for(const auto& component : path.components()) {
      path_str += "/" + component;
  }
  return path_str;
}

struct buffer {
  char *data;
  size_t size;
};

buffer GetEmptyBuffer(size_t size) {
  if(size > MAX_BUFFER_SIZE) {
    size = MAX_BUFFER_SIZE;
  }
  char *buffer = new char[size];
  memset(buffer, 0, size);
  return {buffer, size};
}

void ExecuteCommand(const Command &command) {
  switch(command.command_case()) {
  case Command::kGetattr:
    if(ops.getattr) {
      auto path = GetPath(command.getattr().path());
      struct stat stat{};
      ops.getattr(path.c_str(), &stat, nullptr);
    }
    break;
  case Command::kReadlink:
    if(ops.readlink) {
      auto path = GetPath(command.readlink().path());
      auto buf = GetEmptyBuffer(command.readlink().target().size());
      ops.readlink(path.c_str(), buf.data, buf.size);
      delete[] buf.data;
    }
    break;
  case Command::kMknod:
    if(ops.mknod) {
      auto path = GetPath(command.mknod().path());
      ops.mknod(path.c_str(), command.mknod().mode(), command.mknod().dev());
    }
    break;
  case Command::kMkdir:
    if(ops.mkdir) {
      auto path = GetPath(command.mkdir().path());
      ops.mkdir(path.c_str(), command.mkdir().mode());
    }
    break;
  case Command::kUnlink:
    if(ops.unlink) {
      auto path = GetPath(command.unlink().path());
      ops.unlink(path.c_str());
    }
    break;
  case Command::kRmdir:
    if(ops.rmdir) {
      auto path = GetPath(command.rmdir().path());
        ops.rmdir(path.c_str());
    }
    break;
  case Command::kSymlink:
    if(ops.symlink) {
      auto path = GetPath(command.symlink().path());
      auto target = command.symlink().target();
      ops.symlink(target.c_str(), path.c_str());
    }
    break;
  case Command::kRename:
    if(ops.rename) {
      auto old_path = GetPath(command.rename().old_path());
      auto new_path = GetPath(command.rename().new_path());
      ops.rename(old_path.c_str(), new_path.c_str(), 0);
    }
    break;
  case Command::kLink:
    if(ops.link) {
      auto old_path = GetPath(command.link().old_path());
      auto new_path = GetPath(command.link().new_path());
      ops.link(old_path.c_str(), new_path.c_str());
    }
    break;
  case Command::kChmod:
    if(ops.chmod) {
      auto path = GetPath(command.chmod().path());
      ops.chmod(path.c_str(), command.chmod().mode(), nullptr);
    }
    break;
  case Command::kChown:
    if(ops.chown) {
      auto path = GetPath(command.chown().path());
      ops.chown(path.c_str(), command.chown().uid(), command.chown().gid(), nullptr);
    }
    break;
  case Command::kTruncate:
    if(ops.truncate) {
      auto path = GetPath(command.truncate().path());
      ops.truncate(path.c_str(), command.truncate().size(), nullptr);
    }
    break;
  case Command::kOpen:
    if(ops.open) {
      auto path = GetPath(command.open().path());
      struct fuse_file_info info{};
      info.flags = command.open().flags();
      ops.open(path.c_str(), &info);
    }
    break;
  case Command::kRead:
    if(ops.read) {
      auto path = GetPath(command.read().path());
      auto buf = GetEmptyBuffer(command.read().buf().size());
      ops.read(path.c_str(), buf.data, buf.size, command.read().offset(), nullptr);
      delete[] buf.data;
    }
    break;
  case Command::kWrite:
    if(ops.write) {
        auto path = GetPath(command.write().path());
        auto data = command.write().buf().data();
        ops.write(path.c_str(), data.c_str(), data.size(), command.write().offset(), nullptr);
    }
    break;
  case Command::kStatfs:
    if(ops.statfs) {
      auto path = GetPath(command.statfs().path());
      struct statvfs stat{};
      ops.statfs(path.c_str(), &stat);
    }
    break;
  case Command::kFlush:
    if(ops.flush) {
      auto path = GetPath(command.flush().path());
      ops.flush(path.c_str(), nullptr);
    }
    break;
  case Command::kRelease:
    if(ops.release) {
      auto path = GetPath(command.release().path());
      ops.release(path.c_str(), nullptr);
    }
    break;
  case Command::kFsync:
    if(ops.fsync) {
      auto path = GetPath(command.fsync().path());
      ops.fsync(path.c_str(), 0, nullptr);
    }
    break;
  case Command::kSetxattr:
    if(ops.setxattr) {
      auto path = GetPath(command.setxattr().path());
      auto name = command.setxattr().name();
      auto value = command.setxattr().value().data();
      ops.setxattr(path.c_str(), name.c_str(), value.c_str(), value.size(), 0);
    }
    break;
  case Command::kGetxattr:
    if(ops.getxattr) {
      auto path = GetPath(command.getxattr().path());
      auto name = command.getxattr().name();
      auto buf = GetEmptyBuffer(command.getxattr().value().size());
      ops.getxattr(path.c_str(), name.c_str(), buf.data, buf.size);
      delete[] buf.data;
    }
    break;
  case Command::kListxattr:
    if(ops.listxattr) {
      auto path = GetPath(command.listxattr().path());
      auto buf = GetEmptyBuffer(command.listxattr().list().size());
      ops.listxattr(path.c_str(), buf.data, buf.size);
      delete[] buf.data;
    }
    break;
  case Command::kRemovexattr:
    if(ops.removexattr) {
      auto path = GetPath(command.removexattr().path());
      auto name = command.removexattr().name();
      ops.removexattr(path.c_str(), name.c_str());
    }
    break;
  case Command::kOpendir:
    if(ops.opendir) {
      auto path = GetPath(command.opendir().path());
      ops.opendir(path.c_str(), nullptr);
    }
    break;
  case Command::kReaddir:
    if (ops.readdir) {
      // TODO: supposed to pass a "filler" function, so not super easy
    }
    break;
  case Command::kReleasedir:
    if(ops.releasedir) {
      auto path = GetPath(command.releasedir().path());
      ops.releasedir(path.c_str(), nullptr);
    }
    break;
  case Command::kFsyncdir:
    if(ops.fsyncdir) {
      auto path = GetPath(command.fsyncdir().path());
      ops.fsyncdir(path.c_str(), 0, nullptr);
    }
    break;
  case Command::kAccess:
    if(ops.access) {
      auto path = GetPath(command.access().path());
      ops.access(path.c_str(), command.access().mask());
    }
    break;
  case Command::kCreate:
    if(ops.create) {
      auto path = GetPath(command.create().path());
      ops.create(path.c_str(), command.create().mode(), nullptr);
    }
    break;
  case Command::kLock:
    if(ops.lock) {
      auto path = GetPath(command.lock().path());
      ops.lock(path.c_str(), nullptr, command.lock().cmd(), nullptr);
    }
    break;
  case Command::kUtimens:
    if(ops.utimens) {
      auto path = GetPath(command.utimens().path());
      struct timespec times[2];
      times[0].tv_sec = command.utimens().atime_sec();
      times[0].tv_nsec = command.utimens().atime_nsec();
      times[1].tv_sec = command.utimens().mtime_sec();
      times[1].tv_nsec = command.utimens().mtime_nsec();
      ops.utimens(path.c_str(), times, nullptr);
    }
    break;
  case Command::kBmap:
    if(ops.bmap) {
      auto path = GetPath(command.bmap().path());
      ops.bmap(path.c_str(), command.bmap().blocksize(), nullptr);
    }
    break;
  case Command::kIoctl:
    if(ops.ioctl) {
      // TODO: make better
      auto path = GetPath(command.ioctl().path());
      ops.ioctl(path.c_str(), command.ioctl().cmd(), nullptr, nullptr, command.ioctl().flags(), nullptr);
    }
    break;
  case Command::kPoll:
    if(ops.poll) {
      // TODO: too complicated
    }
    break;
  case Command::kWriteBuf:
    if(ops.write_buf) {
      // TODO: too complicated
    }
    break;
  case Command::kReadBuf:
    if(ops.read_buf) {
      // TODO: too complicated
    }
    break;
  case Command::kFlock:
    if(ops.flock) {
      auto path = GetPath(command.flock().path());
      ops.flock(path.c_str(), nullptr, command.flock().op());
    }
    break;
  case Command::kFallocate:
    if(ops.fallocate) {
        auto path = GetPath(command.fallocate().path());
        ops.fallocate(path.c_str(), command.fallocate().mode(), command.fallocate().offset(), command.fallocate().length(), nullptr);
    }
    break;
  case Command::kCopyFileRange:
    if(ops.copy_file_range) {
        auto path_in = GetPath(command.copy_file_range().path_in());
        auto path_out = GetPath(command.copy_file_range().path_out());
        ops.copy_file_range(path_in.c_str(), nullptr, command.copy_file_range().offset_in(),
                            path_out.c_str(), nullptr, command.copy_file_range().offset_out(),
                            command.copy_file_range().size(), command.copy_file_range().flags());
    }
    break;
  case Command::kLseek:
    if(ops.lseek) {
      auto path = GetPath(command.lseek().path());
      ops.lseek(path.c_str(), command.lseek().offset(), command.lseek().whence(), nullptr);
    }
    break;
  case Command::COMMAND_NOT_SET:break;
  }
}

void ExecuteSession(const Session& session) {
  SetupFs();

  for(const Command& command : session.commands()) {
    ExecuteCommand(command);
  }

  TeardownFs();
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  char* testcase = getenv("TESTCASE");
  if(testcase != nullptr) {
    // read the protobuf at path testcase into a Session and print it to stdin
    std::ifstream ifs(testcase, std::ios::in | std::ios::binary);
    Session session;
    session.ParseFromIstream(&ifs);
    std::cout << session.DebugString();
    ExecuteSession(session);
    exit(0);
  }
  return 0;
}

DEFINE_BINARY_PROTO_FUZZER(const Session& session) {
  ExecuteSession(session);
}
