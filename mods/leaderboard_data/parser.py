import requests
import re

def parse_leaderboard(url):
    response = requests.get(url)
    while response.status_code != 200:
        response = requests.get(url)

    pattern = re.compile(r'<h3>(\d+),\s*([^,]+)\s+(\d+)\s+(\d+\.\d+)</h3>')

    # Find all matches in the HTML content
    matches = re.findall(pattern, response.text)

    # Process the matches into a structured leaderboard
    leaderboard = []
    for match in matches:
        place, username, coin_count, share = match
        # Convert share to a float, then round to 4 decimal places
        share = round(float(share), 4)
        leaderboard.append((place, username.strip(), coin_count, share))

    return leaderboard
