#pragma once

#include <Log/LogMain.hpp>
#include <iostream>
#include <pqxx/pqxx>
#include <Enum/Enum.hpp>
#include <efsw/efsw.hpp>
#include <Thread/Thread.hpp>
#include <Convert/Convert.hpp>
#include <Cryptography/Md5.hpp>
#include <Cryptography/Sha256.hpp>
#include <Cryptography/Sha1.hpp>
#include <Cryptography/Crc32.hpp>
#include <set>
#include <regex>
#include <Bit/Bit.hpp>
#include <deque>

#ifdef CuUtil_Platform_Windows
#undef max
#endif // CuUtil_Platform_Windows

CuEnum_MakeEnum(FileDatabase_ListenerEvent, Update, Delete);

namespace FileDatabase
{
    CuEnum_MakeEnumDef(FdOperator, Watch, Sync);
//    CuEnum_MakeEnumDef(ListenerEvent, Update, Delete);
    using ListenerEvent = FileDatabase_ListenerEvent;

    using QueueType = CuThread::Channel<std::pair<std::filesystem::path, ListenerEvent>>;
    using QueuePtrType = std::shared_ptr<QueueType>;

    static std::atomic_bool SqlExit{ false };

    class UpdateListener : public efsw::FileWatchListener
    {
        QueuePtrType queue;
        std::regex ignore{};

    public:
        UpdateListener(QueuePtrType queue) : queue(queue) {}

        void handleFileAction(efsw::WatchID watchid, const std::string& dir,
            const std::string& filename, efsw::Action action,
            std::string oldFilename) override {
            const auto fullPath = (std::filesystem::path(CuStr::FromDirtyUtf8String(dir)) / CuStr::FromDirtyUtf8String(filename));
            if (std::regex_match(CuStr::ToDirtyUtf8String(fullPath.u8string()), ignore)) return;

            switch (action) {
            case efsw::Actions::Add:
                queue->Emplace(fullPath, ListenerEvent::Update);
                break;
            case efsw::Actions::Delete:
                queue->Emplace(fullPath, ListenerEvent::Delete);
                break;
            case efsw::Actions::Modified:
                queue->Emplace(fullPath, ListenerEvent::Update);
                break;
            case efsw::Actions::Moved:
                queue->Emplace(CuStr::FromDirtyUtf8String(oldFilename), ListenerEvent::Delete);
                queue->Emplace(fullPath, ListenerEvent::Update);
                break;
            default:
                assert(false);
            }
        }
    };

    inline int32_t GetFileStatus(const std::filesystem::path& path)
    {
        try
        {
            auto st = std::filesystem::status(path);

            uint32_t ret = CuUtil::ToUnderlying(st.type()) << 16;
            ret += CuUtil::ToUnderlying(st.permissions());

            return ret;
        }
        catch (const std::exception& ex)
        {
            LogWarn("{}", ex.what());
        }

        return 0;
    }

    inline uint64_t GetFileSize(const std::filesystem::path& path)
    {
        try
        {
            return std::filesystem::file_size(path);
        }
        catch (const std::exception& ex)
        {
            LogWarn("{}", ex.what());
        }

        return 0;
    }

    inline std::string GetLastWriteTime(const std::filesystem::path& path)
    {
        try
        {
#if defined(__APPLE__) || defined(__clang__)
            const auto ft = std::filesystem::last_write_time(path);
            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ft - decltype(ft)::clock::now() + std::chrono::system_clock::now());
            auto tt = std::chrono::system_clock::to_time_t(sctp);
            tm local{};
            CuTime::Local(&local, &tt);
            return CuStr::ToString(std::put_time(&local, "%Y-%m-%d %H:%M:%S"));
#elif defined(__GNUC__) && __GNUC__ < 13
            const auto t = std::chrono::system_clock::to_time_t(std::chrono::file_clock::to_sys(std::filesystem::last_write_time(path)));
            tm local{};
            CuTime::Local(&local, &t);
            return CuStr::ToString(std::put_time(&local, "%Y-%m-%d %H:%M:%S"));
#else
            return CuStr::ToString(std::filesystem::last_write_time(path));
#endif
        }
        catch (const std::exception& ex)
        {
            LogWarn("{}", ex.what());
        }

        return {};
    }

    // md5, sha256, sha1, crc32
    inline std::tuple<std::string, std::string, std::string, std::string> GetFileHash(const std::filesystem::path& path)
    {
        if (std::filesystem::status(path).type() == std::filesystem::file_type::regular)
        {
            try
            {
                const auto sz = std::filesystem::file_size(path);
                CuCrypto::Md5 md5{};
                CuCrypto::Sha256 sha256{};
                CuCrypto::Sha1 sha1{};
                CuCrypto::Crc32 crc32{};

                std::ifstream fs(path, std::ios::in | std::ios::binary);
                if (!fs) return {};

                std::array<uint8_t, 4096> buf{};
                for (size_t i = 0; i < sz;)
                {
                    fs.read((char*)buf.data(), buf.size());
                    const auto count = fs.gcount();
                    if (count <= 0) break;

                    md5.Append(buf.data(), count);
                    sha256.Append(buf.data(), count);
                    sha1.Append(buf.data(), count);
                    crc32.Append(buf.data(), count);
                    i += count;

                    if (count < (int64_t)buf.size()) break;
                    if (!fs) break;
                    if (fs.eof()) break;
                }
                return std::make_tuple(
                    CuStr::Appends("'\\x", md5.Digest().ToString(), "'"),
                    CuStr::Appends("'\\x", sha256.Digest().ToString(), "'"),
                    CuStr::Appends("'\\x", sha1.Digest().ToString(), "'"),
                    CuStr::Appends("'\\x", crc32.Digest().ToString(), "'")
                );
            }
            catch (const std::exception& ex)
            {
                LogWarn("{}", ex.what());
            }
        }

        return {};
    }

    struct SqlHandlerParams
    {
        std::string Device;
        std::string DbUser;
        std::string DbPasword;
        std::string DbHost;
        uint16_t DbPort;
        std::string DbName;
        std::regex Ignore;
        bool OutputToFile;

        bool NoHash;
        std::regex HashSkip;
    };

    inline auto ToLibpqStr(const CuStr::U8StringViewType str)
    {
#if PQXX_VERSION_MAJOR >= 7
        return CuStr::ToDirtyUtf8StringView(str);
#else
        return CuStr::ToDirtyUtf8String(str);
#endif
    }

    inline bool SqlExec(pqxx::work& dbTrans, const CuStr::U8StringViewType sql)
    {
        try
        {
            dbTrans.exec(ToLibpqStr(sql));
        }
        catch (const std::exception& ex)
        {
            LogErr("exec error: {}", CuStr::FromDirtyUtf8String(ex.what()));
            return false;
        }

        dbTrans.commit();
        return true;
    }

    inline bool IsSym(const std::filesystem::path& path)
    {
        std::error_code ec{};
        const auto st = std::filesystem::is_symlink(path, ec);
        if (ec)
        {
            LogWarn("{}", ec.message());
            return false;
        }

        return st;
    }

    inline CuStr::U8StringType GetPathU8(const std::filesystem::path& path)
    {
        try
        {
            return CuStr::ToU8String(path.u8string());
        }
        catch (const std::exception& e)
        {
            LogWarn("{}", e.what());
        }

        return {};
    }

    inline void SqlHandler(const SqlHandlerParams& params, QueuePtrType queue)
    {
        const auto& [device, dbUser, dbPassword, dbHost, dbPort, dbName, ignore, outputToFile, noHash, hashSkip] = params;
        while (true)
        {
            try
            {
                LogInfo("connect {}", dbHost);
                pqxx::connection dbConn(CuStr::Format("user={} password={} host={} port={} dbname={} client_encoding=utf-8 target_session_attrs=read-write",
                    dbUser, dbPassword, dbHost, dbPort, dbName));

                std::fstream outputFs;
                if (outputToFile)
                {
                    outputFs.open("output.txt", std::ios::out | std::ios::app | std::ios::binary);
                    if (!outputFs)
                    {
                        LogErr("open output.txt failed");
                        throw std::exception();
                    }
                }

                while (true)
                {
                    auto [path, event] = queue->Read();
                    if (path.empty()) return;

                    path = path.lexically_normal();

                    const auto u8path = GetPathU8(path);
                    if (u8path.empty()) continue;

                    LogInfo("-> {} {}", CuEnum::ToString(event), u8path);

                    pqxx::work dbTrans(dbConn);
                    if (event == ListenerEvent::Update) {
                        auto st = GetFileStatus(path);
                        auto fs = GetFileSize(path);
                        auto ft = GetLastWriteTime(path);
                        std::string md5{}, sha256{}, sha1{}, crc32{};
                        if (!noHash)
                        {
                            auto pu8 = CuStr::ToDirtyUtf8String(u8path);
                            if (!std::regex_match(pu8, hashSkip))
                            {
                                auto [md5R, sha256R, sha1R, crc32R] = GetFileHash(path);
                                md5 = md5R;
                                sha256 = sha256R;
                                sha1 = sha1R;
                                crc32 = crc32R;
                            }
                        }
                        auto sql = CuStr::AppendsU8(u8"insert into fd (device_name, parent_path, filename, file_status, file_size, last_write_time, file_md5, file_sha256, file_sha1, file_crc32) "
                            "values (",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(device)), u8", ",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(ToLibpqStr(CuStr::ToU8String(path.parent_path())))), u8", ",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(ToLibpqStr(CuStr::ToU8String(path.filename())))), u8", ",
                            CuStr::FromDirtyUtf8String(*CuConv::ToString(st)), u8", ",
                            CuStr::FromDirtyUtf8String(*CuConv::ToString(fs)), u8", ",
                            ft.empty() ? u8"null" : CuStr::FromDirtyUtf8String(dbTrans.quote(ft)), u8", ",
                            md5.empty() ? u8"null" : CuStr::FromDirtyUtf8String(md5), u8", ",
                            sha256.empty() ? u8"null" : CuStr::FromDirtyUtf8String(sha256), u8", ",
                            sha1.empty() ? u8"null" : CuStr::FromDirtyUtf8String(sha1), u8", ",
                            crc32.empty() ? u8"null" : CuStr::FromDirtyUtf8String(crc32),
                            u8") on conflict (device_name, parent_path, filename) do update set "
                            "file_status = excluded.file_status, "
                            "file_size = excluded.file_size, "
                            "last_write_time = excluded.last_write_time, "
                            "file_md5 = excluded.file_md5, "
                            "file_sha256 = excluded.file_sha256, "
                            "file_sha1 = excluded.file_sha1, "
                            "file_crc32 = excluded.file_crc32;"
                        );
                        LogVerb("{}", sql);

                        if (outputToFile)
                        {
                            outputFs.write((const char*)sql.c_str(), sql.length());
                            outputFs.write("\n", 1);
                            outputFs.flush();
                        }
                        else
                        {
                            SqlExec(dbTrans, sql);
                        }
                    }
                    else if (event == ListenerEvent::Delete)
                    {
                        auto sql = CuStr::FormatU8("delete from fd where device_name = {} and parent_path = {} and filename = {};",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(device)),
                            CuStr::FromDirtyUtf8String(dbTrans.quote(ToLibpqStr(CuStr::ToU8String(path.parent_path())))),
                            CuStr::FromDirtyUtf8String(dbTrans.quote(ToLibpqStr(CuStr::ToU8String(path.filename())))));
                        LogVerb("{}", sql);

                        if (outputToFile)
                        {
                            outputFs.write((const char*)sql.c_str(), sql.length());
                            outputFs.write("\n", 1);
                            outputFs.flush();
                        }
                        else
                        {
                            SqlExec(dbTrans, sql);
                        }
                    }
                }
            }
            catch (const std::exception& ex)
            {
                LogErr("error: {}: {}", typeid(ex).name(), ex.what());
            }

            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    inline std::set<std::filesystem::path> GetRoots()
    {
#ifdef CuUtil_Platform_Windows
        constexpr std::string_view AlphaTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        const auto drives = GetLogicalDrives();
        if (drives == 0)
        {
            LogErr("GetLogicalDrives return 0");
            return {};
        }

        std::set<std::filesystem::path> buf{};
        for (auto i = 0; i < AlphaTable.size(); i++)
        {
            if ((drives >> i) & 1)
            {
                std::string root;
                root.push_back(AlphaTable[i]);
                root.append(":\\");
                buf.emplace(root);
            }
        }

        return buf;
#else    
        return { "/" };
#endif
    }

    class Database
    {
    public:
        void Watch(FileDatabase::SqlHandlerParams params, const std::set<std::filesystem::path> roots = GetRoots())
        {
            params.NoHash = true;

            auto queue = std::make_shared<QueueType>();
            queue->DynLimit = 0;

            std::thread sqlThread(SqlHandler, params, queue);

            std::unique_ptr<efsw::FileWatcher> watcher = std::make_unique<efsw::FileWatcher>();
            std::unique_ptr<UpdateListener> listener = std::make_unique<UpdateListener>(queue);

            std::vector<efsw::WatchID> ids{};
            for (const auto& root : roots)
            {
                ids.emplace_back(watcher->addWatch(root.string(), listener.get(), true));
                if (ids.back() < 0) {
                    LogErr("watch {} error: {}", root, ids.back());
                }
            }

            watcher->watch();

            while (!SqlExit)
            {
                using namespace std::chrono_literals;
                std::this_thread::sleep_for(10ms);
            }

            for (const auto& id : ids)
            {
                watcher->removeWatch(id);
            }

            queue->Emplace();

            if (sqlThread.joinable()) sqlThread.join();
        }

        void Sync(FileDatabase::SqlHandlerParams params, const std::set<std::filesystem::path> roots)
        {
            auto queue = std::make_shared<QueueType>();
            queue->DynLimit = 500;

            std::thread sqlThread(SqlHandler, params, queue);

            for (const auto& root : roots)
            {
                const auto pathForLog = [](const std::filesystem::path& path) -> CuStr::U8StringType {
                    try
                    {
                        return CuStr::ToU8String(path);
                    }
                    catch (const std::exception&)
                    {
                        try
                        {
                            return CuStr::ToU8String(path.parent_path()) + u8"/<file>";
                        }
                        catch (const std::exception&)
                        {
                            return u8"<file>";
                        }
                    }
                    };
                std::error_code errorCode;
                std::deque<std::filesystem::path> scanQueue{};
                const std::filesystem::directory_iterator end;
                scanQueue.emplace_back(root);
                while (!scanQueue.empty())
                {
                    try
                    {
                        for (std::filesystem::directory_iterator file(scanQueue.front(), std::filesystem::directory_options::skip_permission_denied, errorCode); file != end; ++file)
                        {
                            try
                            {
                                if (errorCode)
                                {
                                    LogWarn("scan: {} {}", pathForLog(file->path()), errorCode.message());
                                    errorCode.clear();
                                    continue;
                                }

                                auto testU8 = false;
                                std::string dirtyU8{};
                                try
                                {
                                    dirtyU8 = CuStr::ToDirtyUtf8String(CuStr::ToU8String(file->path()));
                                    testU8 = true;
                                }
                                catch (const std::exception&)
                                {
                                    LogWarn("scan: {}: cvt u8 error", pathForLog(file->path()));
                                }

                                if (!testU8) continue;
                                if (std::regex_match(dirtyU8, params.Ignore)) continue;

                                auto isSym = file->is_symlink(errorCode);
                                if (errorCode)
                                {
                                    LogWarn("scan: {} {}", file->path(), errorCode.message());
                                    errorCode.clear();
                                    isSym = false;
                                }
                                if (isSym) continue;

                                auto st = file->status(errorCode);
                                auto isDir = false;
                                if (errorCode)
                                {
                                    LogWarn("scan: {} {}", file->path(), errorCode.message());
                                    errorCode.clear();
                                }
                                else
                                {
                                    if (st.type() == std::filesystem::file_type::directory) isDir = true;
                                }

                                if (isDir)
                                {
                                    scanQueue.emplace_back(file->path());
                                }

                                queue->Emplace(file->path(), ListenerEvent::Update);
                            }
                            catch (const std::exception& e)
                            {
                                LogErr("scan: {} {}", file->path().u8string(), e.what());
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        LogErr("scan: {} {}", scanQueue.front(), e.what());
                    }
                    scanQueue.pop_front();
                }
            }

            queue->Emplace();

            if (sqlThread.joinable()) sqlThread.join();
        }
    };
};

CuEnum_MakeEnumSpec(FileDatabase, FdOperator);
//CuEnum_MakeEnumSpec(FileDatabase, ListenerEvent);
