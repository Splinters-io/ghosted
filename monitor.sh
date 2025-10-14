#!/bin/bash

# Ghosted V8 - Continuous Monitoring Script
# Run in screen: screen -S ghosted-monitor ./monitor.sh

# Configuration
REFRESH_INTERVAL=600  # 10 minutes (600 seconds)
OUTPUT_DIR="output"
TIMESTAMP_FORMAT="%Y-%m-%d %H:%M:%S"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print header
print_header() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}GHOSTED V8 - CONTINUOUS MONITORING DASHBOARD${NC}                              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Last Updated:${NC} $(date +"${TIMESTAMP_FORMAT}")"
    echo -e "${YELLOW}Next Refresh:${NC} $(date -d "+${REFRESH_INTERVAL} seconds" +"${TIMESTAMP_FORMAT}")"
    echo ""
}

# Function to get impact folder statistics
get_impact_stats() {
    local total_scans=$(find "$OUTPUT_DIR" -type d -name "impact" 2>/dev/null | wc -l)
    local total_domains=$(find "$OUTPUT_DIR"/*/impact -name "*.md" 2>/dev/null | wc -l)

    echo "$total_scans|$total_domains"
}

# Function to get PublicWWW research statistics
get_publicwww_stats() {
    local total_researched=0
    local scans_with_research=0

    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local count=$(sqlite3 "$scan/database.db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")
            if [ "$count" -gt 0 ]; then
                total_researched=$((total_researched + count))
                scans_with_research=$((scans_with_research + 1))
            fi
        fi
    done

    echo "$scans_with_research|$total_researched"
}

# Function to get SENDIT report count
get_sendit_reports() {
    find "$OUTPUT_DIR" -name "SENDIT_REPORT.md" 2>/dev/null | wc -l
}

# Function to display top available domains by impact
show_top_domains() {
    echo -e "\n${CYAN}═══ TOP AVAILABLE DOMAINS BY AFFECTED APPLICATIONS ═══${NC}\n"

    local count=0
    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            sqlite3 "$scan/database.db" "
                SELECT
                    a.domain,
                    COUNT(DISTINCT t.origin_domain) as affected_count,
                    (SELECT COUNT(*) FROM publicwww_results p WHERE p.domain = a.domain) as pww_count
                FROM availability_checks a
                LEFT JOIN trust_relationships t ON a.domain = t.external_domain
                WHERE a.status = 'AVAILABLE'
                GROUP BY a.domain
                ORDER BY affected_count DESC, pww_count DESC
            " 2>/dev/null | while IFS='|' read -r domain affected pww; do
                if [ -n "$domain" ] && [ "$affected" -gt 0 ]; then
                    local pww_text=""
                    if [ "$pww" -gt 0 ]; then
                        pww_text="${GREEN}[${pww} sites via PublicWWW]${NC}"
                    else
                        pww_text="${YELLOW}[Not researched]${NC}"
                    fi
                    printf "  ${RED}%-35s${NC} → ${YELLOW}%3d applications${NC} %b\n" "$domain" "$affected" "$pww_text"
                    count=$((count + 1))
                fi
            done
        fi
    done

    if [ "$count" -eq 0 ]; then
        echo -e "  ${YELLOW}No available domains found yet.${NC}"
    fi
}

# Function to display recent scans
show_recent_scans() {
    echo -e "\n${CYAN}═══ RECENT SCANS (Last 10) ═══${NC}\n"

    find "$OUTPUT_DIR" -maxdepth 1 -type d -name "beast_*" -o -name "scan_*" 2>/dev/null | \
        sort -r | head -10 | while read -r scan; do
        local scan_name=$(basename "$scan")
        local db="$scan/database.db"

        if [ -f "$db" ]; then
            local available=$(sqlite3 "$db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")
            local researched=$(sqlite3 "$db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")
            local has_sendit=""

            if [ -f "$scan/SENDIT_REPORT.md" ]; then
                has_sendit="${GREEN}[SENDIT]${NC}"
            fi

            if [ "$available" -gt 0 ]; then
                printf "  ${YELLOW}%-50s${NC} → ${RED}%2d available${NC} | ${CYAN}%2d researched${NC} %b\n" \
                    "$scan_name" "$available" "$researched" "$has_sendit"
            else
                printf "  ${YELLOW}%-50s${NC} → ${GREEN}No available domains${NC}\n" "$scan_name"
            fi
        fi
    done
}

# Function to auto-perform research on scans that need it
auto_perform_research() {
    local count=0
    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local available=$(sqlite3 "$scan/database.db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")
            local researched=$(sqlite3 "$scan/database.db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")

            if [ "$available" -gt 0 ] && [ "$researched" -eq 0 ]; then
                local scan_name=$(basename "$scan")
                echo -e "\n${CYAN}[AUTO-RESEARCH]${NC} Starting research for ${YELLOW}${scan_name}${NC}..."
                ./ghosted research "$scan" 2>&1 | tee -a "$scan/auto_research.log"
                count=$((count + 1))
            fi
        fi
    done
    return $count
}

# Function to display scans needing research
show_needs_research() {
    echo -e "\n${CYAN}═══ SCANS NEEDING PUBLICWWW RESEARCH ═══${NC}\n"

    local count=0
    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local available=$(sqlite3 "$scan/database.db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")
            local researched=$(sqlite3 "$scan/database.db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")

            if [ "$available" -gt 0 ] && [ "$researched" -eq 0 ]; then
                local scan_name=$(basename "$scan")
                printf "  ${RED}%-50s${NC} → ${YELLOW}%d available domain(s)${NC}\n" "$scan_name" "$available"
                count=$((count + 1))
            fi
        fi
    done

    if [ "$count" -eq 0 ]; then
        echo -e "  ${GREEN}All scans with available domains have been researched!${NC}"
    else
        echo -e "  ${YELLOW}Total scans needing research: ${RED}${count}${NC}"
        echo -e "  ${GREEN}[AUTO] Will perform research automatically...${NC}"
    fi
}

# Function to auto-generate SENDIT reports on scans that need them
auto_perform_sendit() {
    local count=0
    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local available=$(sqlite3 "$scan/database.db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")

            if [ "$available" -gt 0 ] && [ ! -f "$scan/SENDIT_REPORT.md" ]; then
                local scan_name=$(basename "$scan")
                echo -e "\n${CYAN}[AUTO-SENDIT]${NC} Generating SENDIT report for ${YELLOW}${scan_name}${NC}..."
                ./ghosted sendit "$scan" 2>&1 | tee -a "$scan/auto_sendit.log"
                count=$((count + 1))
            fi
        fi
    done
    return $count
}

# Function to display scans needing SENDIT reports
show_needs_sendit() {
    echo -e "\n${CYAN}═══ SCANS NEEDING SENDIT REPORTS ═══${NC}\n"

    local count=0
    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local available=$(sqlite3 "$scan/database.db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")

            if [ "$available" -gt 0 ] && [ ! -f "$scan/SENDIT_REPORT.md" ]; then
                local scan_name=$(basename "$scan")
                local researched=$(sqlite3 "$scan/database.db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")

                printf "  ${RED}%-50s${NC} → ${YELLOW}%d available${NC} | ${CYAN}%d researched${NC}\n" \
                    "$scan_name" "$available" "$researched"
                count=$((count + 1))
            fi
        fi
    done

    if [ "$count" -eq 0 ]; then
        echo -e "  ${GREEN}All scans with available domains have SENDIT reports!${NC}"
    else
        echo -e "  ${YELLOW}Total scans needing SENDIT reports: ${RED}${count}${NC}"
        echo -e "  ${GREEN}[AUTO] Will generate SENDIT reports automatically...${NC}"
    fi
}

# Function to display actionable summary
show_actionable_summary() {
    echo -e "\n${CYAN}═══ ACTIONABLE ITEMS SUMMARY ═══${NC}\n"

    # Count scans needing research
    local needs_research=0
    local needs_sendit=0
    local total_unreported_domains=0

    for scan in "$OUTPUT_DIR"/beast_* "$OUTPUT_DIR"/scan_*; do
        if [ -f "$scan/database.db" ]; then
            local available=$(sqlite3 "$scan/database.db" "SELECT COUNT(*) FROM availability_checks WHERE status='AVAILABLE'" 2>/dev/null || echo "0")
            local researched=$(sqlite3 "$scan/database.db" "SELECT COUNT(DISTINCT domain) FROM publicwww_results" 2>/dev/null || echo "0")

            if [ "$available" -gt 0 ]; then
                if [ "$researched" -eq 0 ]; then
                    needs_research=$((needs_research + 1))
                fi

                if [ ! -f "$scan/SENDIT_REPORT.md" ]; then
                    needs_sendit=$((needs_sendit + 1))
                    total_unreported_domains=$((total_unreported_domains + available))
                fi
            fi
        fi
    done

    if [ "$needs_research" -gt 0 ]; then
        echo -e "  ${RED}[!]${NC}  ${YELLOW}${needs_research} scan(s) need PublicWWW research${NC}"
    fi

    if [ "$needs_sendit" -gt 0 ]; then
        echo -e "  ${RED}[!]${NC}  ${YELLOW}${needs_sendit} scan(s) need SENDIT reports (${total_unreported_domains} unreported domains)${NC}"
    fi

    if [ "$needs_research" -eq 0 ] && [ "$needs_sendit" -eq 0 ]; then
        echo -e "  ${GREEN}[OK]${NC}  ${GREEN}All scans are up to date!${NC}"
    fi
}

# Main monitoring loop
main() {
    while true; do
        print_header

        # Get statistics
        IFS='|' read -r total_scans total_domains <<< "$(get_impact_stats)"
        IFS='|' read -r researched_scans researched_domains <<< "$(get_publicwww_stats)"
        local sendit_reports=$(get_sendit_reports)

        # Display overview
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}═══ OVERVIEW ═══${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        printf "  ${YELLOW}%-40s${NC} ${RED}%5d${NC}\n" "Total scans with available domains:" "$total_scans"
        printf "  ${YELLOW}%-40s${NC} ${RED}%5d${NC}\n" "Total available domains found:" "$total_domains"
        printf "  ${YELLOW}%-40s${NC} ${CYAN}%5d${NC}\n" "Scans with PublicWWW research:" "$researched_scans"
        printf "  ${YELLOW}%-40s${NC} ${CYAN}%5d${NC}\n" "Domains researched via PublicWWW:" "$researched_domains"
        printf "  ${YELLOW}%-40s${NC} ${GREEN}%5d${NC}\n" "SENDIT reports generated:" "$sendit_reports"
        echo ""

        # Display actionable summary
        show_actionable_summary

        # Display detailed sections
        show_top_domains
        show_recent_scans
        show_needs_research
        show_needs_sendit

        # AUTO-PERFORM RESEARCH AND SENDIT
        echo -e "\n${CYAN}═══ AUTOMATED OPERATIONS ═══${NC}\n"

        # Perform research on scans that need it
        auto_perform_research
        local research_count=$?
        if [ "$research_count" -gt 0 ]; then
            echo -e "${GREEN}[AUTO-RESEARCH]${NC} Completed research for ${CYAN}${research_count}${NC} scan(s)"
        fi

        # Perform SENDIT on scans that need it
        auto_perform_sendit
        local sendit_count=$?
        if [ "$sendit_count" -gt 0 ]; then
            echo -e "${GREEN}[AUTO-SENDIT]${NC} Generated SENDIT reports for ${CYAN}${sendit_count}${NC} scan(s)"
        fi

        if [ "$research_count" -eq 0 ] && [ "$sendit_count" -eq 0 ]; then
            echo -e "  ${GREEN}No automated operations needed at this time.${NC}"
        fi

        # Footer
        echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}Monitoring active. Press Ctrl+C to stop.${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}\n"

        # Wait for next refresh
        sleep "$REFRESH_INTERVAL"
    done
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n\n${YELLOW}Monitoring stopped.${NC}\n"; exit 0' INT TERM

# Start monitoring
main
