"use client";

import { useState, useEffect } from "react";

type Movie = { title: string; src: string };

// Your actual files from public/movie-assets/
const MOVIES: Movie[] = [
  { title: "3 Idiots", src: "/movie-assets/3-ediot.jpg" },
  { title: "The Imitation Game", src: "/movie-assets/immitation-game.jpg" },
  { title: "Interstellar", src: "/movie-assets/interstellar.jpg" },
  { title: "Chhichhore", src: "/movie-assets/chichore.jpg" },
  { title: "Mission Mangal", src: "/movie-assets/mission-mangal.jpg" },
  { title: "Oppenheimer", src: "/movie-assets/openheimer.jpg" },
  { title: "The Social Network", src: "/movie-assets/social-network.jpg" },
  { title: "Swades", src: "/movie-assets/swadesh.png" },
];

const BLURBS: Record<string, string> = {
  "3 Idiots": "Three engineering students navigate friendship, pressure, and the real meaning of success.",
  "The Imitation Game": "A codebreaker races to crack a wartime cipher against impossible odds.",
  "Interstellar": "A crew ventures through a wormhole in search of a new home for humanity.",
  "Chhichhore": "College friends look back on failure, resilience, and what really matters.",
  "Mission Mangal": "A team of scientists chases an ambitious, low-budget dream of reaching Mars.",
  "Oppenheimer": "The story of the physicist behind the atomic bomb and its aftermath.",
  "The Social Network": "The messy, high-stakes origin story of a social media empire.",
  "Swades": "An NRI returns home and reconnects with his roots and his village.",
};

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Inline SVG icons — no external package needed
const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.3-4.3" />
  </svg>
);
const BellIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
    <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
  </svg>
);
const ChevronDownIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4">
    <path d="m6 9 6 6 6-6" />
  </svg>
);
const PlayIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" className="h-5 w-5">
    <path d="M8 5v14l11-7z" />
  </svg>
);
const InfoIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
    <circle cx="12" cy="12" r="10" />
    <path d="M12 16v-4" />
    <path d="M12 8h.01" />
  </svg>
);

export default function Home() {
  const [scrolled, setScrolled] = useState(false);

  // Deterministic on first render (server + client match) — shuffled after mount only
  const [hero, setHero] = useState<Movie>(MOVIES[0]);
  const [trending, setTrending] = useState<Movie[]>(MOVIES);
  const [demoPicks, setDemoPicks] = useState<Movie[]>(MOVIES);
  const [newReleases, setNewReleases] = useState<Movie[]>(MOVIES);
  const [topPicks, setTopPicks] = useState<Movie[]>(MOVIES);

  useEffect(() => {
    const shuffled = shuffle(MOVIES);
    setHero(shuffled[0]);
    setTrending(shuffle(MOVIES));
    setDemoPicks(shuffle(MOVIES));
    setNewReleases(shuffle(MOVIES));
    setTopPicks(shuffle(MOVIES));
  }, []);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const rows = [
    { title: "Trending Now", items: trending },
    { title: "IDS Demo Picks", items: demoPicks },
    { title: "New Releases", items: newReleases },
  ];

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Navbar */}
      <nav
        className={`fixed top-0 z-50 flex w-full items-center justify-between px-4 py-4 transition-colors duration-300 md:px-12 ${
          scrolled ? "bg-black" : "bg-gradient-to-b from-black/80 to-transparent"
        }`}
      >
        <div className="flex items-center gap-8">
          <span className="text-2xl font-bold tracking-tight text-red-600">
            CINEFLIX EDU
          </span>
          <ul className="hidden gap-5 text-sm text-gray-200 md:flex">
            <li className="cursor-pointer font-semibold text-white">Home</li>
            <li className="cursor-pointer hover:text-gray-300">TV Shows</li>
            <li className="cursor-pointer hover:text-gray-300">Movies</li>
            <li className="cursor-pointer hover:text-gray-300">New & Popular</li>
            <li className="cursor-pointer hover:text-gray-300">My List</li>
          </ul>
        </div>

        <div className="flex items-center gap-4 text-gray-200">
          <span className="cursor-pointer hover:text-white"><SearchIcon /></span>
          <span className="cursor-pointer hover:text-white"><BellIcon /></span>
          <div className="flex cursor-pointer items-center gap-1">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-red-600 text-sm font-bold text-white">
              A
            </div>
            <ChevronDownIcon />
          </div>
        </div>
      </nav>

      {/* Hero / Spotlight */}
      <div className="relative h-[85vh] w-full">
        <img src={hero.src} alt={hero.title} className="h-full w-full object-cover" />
        <div className="absolute inset-0 bg-gradient-to-r from-black via-black/40 to-transparent" />
        <div className="absolute inset-x-0 bottom-0 h-1/2 bg-gradient-to-t from-black to-transparent" />

        <div className="absolute bottom-[20%] left-4 max-w-xl md:left-12">
          <h1 className="text-4xl font-bold drop-shadow-lg md:text-6xl">{hero.title}</h1>
          <p className="mt-4 text-sm text-gray-200 drop-shadow md:text-base">
            {BLURBS[hero.title]}
          </p>
          <div className="mt-5 flex gap-3">
            <button className="flex items-center gap-2 rounded bg-white px-6 py-2 font-semibold text-black transition hover:bg-white/80">
              <PlayIcon /> Play
            </button>
            <button className="flex items-center gap-2 rounded bg-gray-500/40 px-6 py-2 font-semibold text-white backdrop-blur transition hover:bg-gray-500/60">
              <InfoIcon /> More Info
            </button>
          </div>
        </div>
      </div>

      {/* Rows */}
      <div className="relative z-10 -mt-24 space-y-10 pb-16">
        {/* Top Picks row with rank numbers */}
        <div className="px-4 md:px-12">
          <h2 className="mb-2 text-lg font-semibold text-gray-100 md:text-xl">
            Top Picks Today
          </h2>
          <div className="flex gap-4 overflow-x-scroll scroll-smooth pb-4">
            {topPicks.map((movie, i) => (
              <div key={movie.title} className="flex flex-none items-end">
                <span className="-mr-3 select-none text-[70px] font-black leading-none text-transparent [-webkit-text-stroke:2px_#3a3a3a] md:text-[100px]">
                  {i + 1}
                </span>
                <div className="group relative aspect-[2/3] w-[110px] flex-none cursor-pointer overflow-hidden rounded-md shadow-lg transition-transform duration-300 hover:z-20 hover:scale-110 hover:shadow-2xl md:w-[140px]">
                  <img src={movie.src} alt={movie.title} className="h-full w-full object-cover" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {rows.map((row) => (
          <div key={row.title} className="px-4 md:px-12">
            <h2 className="mb-2 text-lg font-semibold text-gray-100 md:text-xl">
              {row.title}
            </h2>
            <div className="flex gap-3 overflow-x-scroll scroll-smooth pb-4">
              {row.items.map((movie, i) => (
                <div
                  key={movie.title + i}
                  className="group relative aspect-[2/3] w-[140px] flex-none cursor-pointer overflow-hidden rounded-md shadow-lg transition-transform duration-300 hover:z-20 hover:scale-110 hover:shadow-2xl md:w-[170px]"
                >
                  <img src={movie.src} alt={movie.title} className="h-full w-full object-cover" />
                  <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent p-2 pt-6 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                    <p className="truncate text-xs font-medium text-white">{movie.title}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-800 px-4 py-10 text-sm text-gray-500 md:px-12">
        <p className="mb-4">
          CineFlix EDU — dummy academic project for IDS demonstration purposes only.
        </p>
        <div className="grid max-w-2xl grid-cols-2 gap-2 md:grid-cols-4">
          <span className="cursor-pointer hover:underline">FAQ</span>
          <span className="cursor-pointer hover:underline">Help Center</span>
          <span className="cursor-pointer hover:underline">Account</span>
          <span className="cursor-pointer hover:underline">Media Center</span>
          <span className="cursor-pointer hover:underline">Investor Relations</span>
          <span className="cursor-pointer hover:underline">Jobs</span>
          <span className="cursor-pointer hover:underline">Ways to Watch</span>
          <span className="cursor-pointer hover:underline">Terms of Use</span>
        </div>
      </footer>
    </div>
  );
}