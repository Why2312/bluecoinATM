import requests
from bs4 import BeautifulSoup

def parse_leaderboard(url):
    response = requests.get(url)
    while response.status_code != 200:
        response = requests.get(url)


    soup = BeautifulSoup(response.content, 'html.parser')
    leaderboard_items = soup.find_all('h3')

    leaderboard = []
    for item in leaderboard_items:
        text = item.get_text()
        parts = text.split(', ')
        if len(parts) >= 2:
            place = parts[0]
            rest = ' '.join(parts[1:]).rsplit(' ', 2)
            if len(rest) == 3:
                username, coin_count, share = rest
                leaderboard.append((place, username, coin_count, share))

    return leaderboard
