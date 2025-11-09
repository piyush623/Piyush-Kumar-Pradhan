// sysmon.cpp
// Compile: g++ -std=c++17 sysmon.cpp -lncurses -o sysmon
// Run: ./sysmon
//
// Simple system monitor using /proc and ncurses.
// Keys: q = quit, s = toggle sort (CPU <-> MEM), k = kill PID, r = change refresh interval

#include <ncurses.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <iomanip>
#include <iostream>
#include <cctype>

struct ProcInfo {
    int pid{0};
    std::string user;
    std::string cmd;
    unsigned long utime{0}, stime{0}, cutime{0}, cstime{0};
    unsigned long long total_time{0};
    unsigned long vsize{0};
    long rss{0};
    double cpu_percent{0.0};
    double mem_percent{0.0};
    unsigned long long starttime{0};
};

struct SystemSnapshot {
    unsigned long long total_jiffies{0};
    unsigned long mem_total_kb{0};
    unsigned long mem_free_kb{0};
    unsigned long mem_available_kb{0};
    int num_cpus{1};
};

static inline std::vector<std::string> split(const std::string &s, char delim=' ') {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!item.empty())
            out.push_back(item);
    }
    return out;
}

unsigned long long read_total_jiffies() {
    std::ifstream f("/proc/stat");
    std::string line;
    if (!std::getline(f, line)) return 0;
    std::stringstream ss(line);
    std::string cpu;
    ss >> cpu;
    unsigned long long val, total = 0;
    while (ss >> val) total += val;
    return total;
}

SystemSnapshot read_system_snapshot() {
    SystemSnapshot s;
    s.total_jiffies = read_total_jiffies();

    std::ifstream memf("/proc/meminfo");
    std::string key;
    unsigned long val;
    while (memf >> key >> val) {
        if (key == "MemTotal:") s.mem_total_kb = val;
        else if (key == "MemFree:") s.mem_free_kb = val;
        else if (key == "MemAvailable:") s.mem_available_kb = val;
    }

    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    int cpus = 0;
    while (std::getline(cpuinfo, line)) {
        if (line.rfind("processor", 0) == 0) cpus++;
    }
    s.num_cpus = std::max(1, cpus);

    return s;
}

std::string read_cmdline(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream f(path);
    std::string s;
    std::getline(f, s, '\0');
    if (s.empty()) {
        std::ifstream g("/proc/" + std::to_string(pid) + "/comm");
        std::getline(g, s);
        return s;
    }
    for (auto &ch : s) if (ch == '\0') ch = ' ';
    return s;
}

std::map<int, ProcInfo> read_all_procs() {
    std::map<int, ProcInfo> procs;
    DIR *d = opendir("/proc");
    if (!d) return procs;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!isdigit(de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        std::string statp = "/proc/" + std::to_string(pid) + "/stat";
        std::ifstream f(statp);
        if (!f) continue;
        std::string statline;
        std::getline(f, statline);
        auto p1 = statline.find('(');
        auto p2 = statline.rfind(')');
        if (p1==std::string::npos || p2==std::string::npos) continue;
        std::string comm = statline.substr(p1+1, p2-p1-1);

        std::ifstream f2(statp);
        if (!f2) continue;
        std::string full;
        std::getline(f2, full);
        size_t rp = full.rfind(')');
        if (rp == std::string::npos) continue;
        std::string after = full.substr(rp+2);
        auto toks = split(after, ' ');
        unsigned long utime=0, stime=0, cutime=0, cstime=0;
        unsigned long long starttime = 0;
        unsigned long vsize = 0;
        long rss = 0;
        if (toks.size() >= 22) {
            try {
                utime = std::stoul(toks[11]);
                stime = std::stoul(toks[12]);
                cutime = std::stoul(toks[13]);
                cstime = std::stoul(toks[14]);
                starttime = std::stoull(toks[19]);
                vsize = std::stoul(toks[20]);
                rss = std::stol(toks[21]);
            } catch(...) {}
        }

        ProcInfo p;
        p.pid = pid;
        p.cmd = read_cmdline(pid);
        p.utime = utime; p.stime = stime; p.cutime = cutime; p.cstime = cstime;
        p.total_time = (unsigned long long)utime + stime + cutime + cstime;
        p.starttime = starttime;
        p.vsize = vsize;
        p.rss = rss;
        procs[pid] = p;
    }
    closedir(d);
    return procs;
}

void compute_cpu_mem_percent(std::map<int, ProcInfo> &procs,
                             const std::map<int, ProcInfo> &prev,
                             const SystemSnapshot &cur_snap,
                             const SystemSnapshot &prev_snap) {
    unsigned long long total_diff = 0;
    if (cur_snap.total_jiffies >= prev_snap.total_jiffies)
        total_diff = cur_snap.total_jiffies - prev_snap.total_jiffies;
    else total_diff = 0;

    static long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;

    for (auto &kv : procs) {
        int pid = kv.first;
        ProcInfo &p = kv.second;
        p.cpu_percent = 0.0;
        p.mem_percent = 0.0;

        auto it = prev.find(pid);
        if (it != prev.end() && total_diff > 0) {
            unsigned long long prev_time = it->second.total_time;
            unsigned long long diff = (p.total_time >= prev_time) ? (p.total_time - prev_time) : 0;
            p.cpu_percent = (double)diff / (double)total_diff * 100.0 * cur_snap.num_cpus;
        }

        long rss_pages = p.rss;
        long rss_kb = rss_pages * page_size_kb;
        if (cur_snap.mem_total_kb > 0)
            p.mem_percent = (double)rss_kb / (double)cur_snap.mem_total_kb * 100.0;
    }
}

void draw_header(WINDOW *w, int width, const SystemSnapshot &snap) {
    werase(w);
    mvwprintw(w, 0, 0, " SysMon - Simple System Monitor (q:quit  s:sort CPU/MEM  k:kill PID  r:refresh time) ");
    mvwprintw(w, 1, 0, " CPUs: %d | Total Jiffies: %llu | MemTotal: %lu KB ", snap.num_cpus, snap.total_jiffies, snap.mem_total_kb);
    mvwprintw(w, 2, 0, " PID    CPU%%    MEM%%    RSS(KB)    CMD");
    wrefresh(w);
}

void draw_processes(WINDOW *w, const std::vector<ProcInfo> &plist, int start, int height) {
    werase(w);
    int row = 0;
    for (int i = start; i < (int)plist.size() && row < height; ++i, ++row) {
        const ProcInfo &p = plist[i];
        long rss_kb = p.rss * (sysconf(_SC_PAGESIZE) / 1024);
        mvwprintw(w, row, 0, "%5d %7.2f %8.2f %10ld  %.60s", p.pid, p.cpu_percent, p.mem_percent, rss_kb, p.cmd.c_str());
    }
    wrefresh(w);
}

int main() {
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    curs_set(0);

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    WINDOW *header = newwin(3, cols, 0, 0);
    WINDOW *procwin = newwin(rows - 3, cols, 3, 0);

    SystemSnapshot prev_snap = read_system_snapshot();
    auto prev_procs = read_all_procs();

    int refresh_interval = 2;
    bool sort_by_cpu = true;
    int offset = 0;

    while (true) {
        SystemSnapshot cur_snap = read_system_snapshot();
        auto cur_procs = read_all_procs();
        compute_cpu_mem_percent(cur_procs, prev_procs, cur_snap, prev_snap);

        std::vector<ProcInfo> plist;
        for (auto &kv : cur_procs) plist.push_back(kv.second);

        if (sort_by_cpu)
            std::sort(plist.begin(), plist.end(), [](const ProcInfo &a, const ProcInfo &b){
                return a.cpu_percent > b.cpu_percent;
            });
        else
            std::sort(plist.begin(), plist.end(), [](const ProcInfo &a, const ProcInfo &b){
                return a.mem_percent > b.mem_percent;
            });

        draw_header(header, cols, cur_snap);
        draw_processes(procwin, plist, offset, rows - 3);

        int ch = getch();
        if (ch != ERR) {
            if (ch == 'q' || ch == 'Q') break;
            else if (ch == 's' || ch == 'S') sort_by_cpu = !sort_by_cpu;
            else if (ch == KEY_DOWN && offset + (rows-3) < (int)plist.size()) offset++;
            else if (ch == KEY_UP && offset > 0) offset--;
        }

        prev_snap = cur_snap;
        prev_procs = cur_procs;

        std::this_thread::sleep_for(std::chrono::seconds(refresh_interval));
    }

    delwin(header);
    delwin(procwin);
    endwin();
    return 0;
}

